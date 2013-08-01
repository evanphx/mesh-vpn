package main

import (
	"bytes"
	"code.google.com/p/tuntap"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
	"github.com/evanphx/go-crypto-dh/dh"
	"net"
	"os/exec"
)

type Ethernet struct {
	SrcMAC, DstMAC net.HardwareAddr
	// Length is only set if a length field exists within this header.  Ethernet
	// headers follow two different standards, one that uses an EthernetType, the
	// other which defines a length the follows with a LLC header (802.3).  If the
	// former is the case, we set EthernetType and Length stays 0.  In the latter
	// case, we set Length and EthernetType = EthernetTypeLLC.
	Length uint16
}

type Frame struct {
	Input bool
	From  *net.UDPAddr
	Data  []byte
}

type Peer struct {
	Addr *net.UDPAddr

	Negotiated bool

	PrivKey *dh.PrivateKey
	PubKey  *dh.SlimPublicKey
	Secret  *dh.Secret

	Key, IV []byte
	MacKey  []byte
	MacLen  int

	Block  cipher.Block
	Stream cipher.Stream

	SeqIn, SeqOut uint32
}

type Peers map[string]*Peer

func (eth *Ethernet) DecodeFromBytes(data []byte) error {
	if len(data) < 14 {
		return errors.New("Ethernet packet too small")
	}

	eth.DstMAC = net.HardwareAddr(data[0:6])
	eth.SrcMAC = net.HardwareAddr(data[6:12])
	eth.Length = binary.BigEndian.Uint16(data[12:14])

	return nil
}

func Route(conn net.PacketConn, tun *tuntap.Interface) {
	buf := make([]byte, 10000)

	for {
		count, _, _ := conn.ReadFrom(buf)

		fmt.Printf("Input %d bytes\n", count)

		pkt := tuntap.Packet{}
		pkt.Protocol = 0x8000
		pkt.Truncated = false
		pkt.Packet = buf[0:count]

		tun.WritePacket(&pkt)
	}
}

func Route2(conn net.Conn, tun *tuntap.Interface) {
	buf := make([]byte, 10000)

	for {
		count, _ := conn.Read(buf)

		fmt.Printf("Input %d bytes\n", count)

		pkt := tuntap.Packet{}
		pkt.Protocol = 0x8000
		pkt.Truncated = false
		pkt.Packet = buf[0:count]

		tun.WritePacket(&pkt)
	}
}

func ReadUDP(conn *net.UDPConn, proc chan *Frame) {
	for {
		buf := make([]byte, 10000)
		count, addr, _ := conn.ReadFromUDP(buf)

		fmt.Printf("Input %d bytes\n", count)

		proc <- &Frame{true, addr, buf[0:count]}
	}
}

func ReadDevice(tun *tuntap.Interface, proc chan *Frame) {
	for {
		pkt, err := tun.ReadPacket()
		if err != nil {
			fmt.Println("Read error:", err)
		} else {
			if pkt.Truncated {
				fmt.Printf("!")
			} else {
				fmt.Printf(" ")
			}
			fmt.Printf("%x %x\n", pkt.Protocol, pkt.Packet)

			eth := &Ethernet{}
			eth.DecodeFromBytes(pkt.Packet)

			fmt.Printf("dst: %s, src: %s\n", eth.DstMAC.String(), eth.SrcMAC.String())

			proc <- &Frame{false, nil, pkt.Packet}
		}
	}
}

var defaultGroup = dh.Group14
var keyInfo = []byte("diffie-hellman-group14-sha256-mesh-vpn")
var IVkeyInfo = []byte("diffie-hellman-group14-sha256-mesh-vpn-IV")
var macInfo = []byte("diffie-hellman-group14-sha256-mesh-vpn-mac")

type negotiationData struct {
	Key dh.SlimPublicKey
}

func makeNegotiate(peer *Peer) []byte {
	var buf bytes.Buffer

	_, err := buf.Write([]byte{0})

	if err != nil {
		panic(err)
	}

	if peer.PrivKey == nil {
		privkey, err := dh.MakeKey(rand.Reader, defaultGroup)

		if err != nil {
			panic(err)
		}

		peer.PrivKey = privkey
	}

	enc := gob.NewEncoder(&buf)

	err = enc.Encode(negotiationData{*peer.PrivKey.SlimPub()})

	if err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func readNegotiate(frame *Frame, peer *Peer) bool {
	var buf bytes.Buffer

	fmt.Println("reading nego...")

	buf.Write(frame.Data[1:])

	dec := gob.NewDecoder(&buf)

	var data negotiationData

	err := dec.Decode(&data)

	if err != nil {
		panic(err)
	}

	reply := false

	if peer.PrivKey == nil {
		privkey, err := dh.MakeKey(rand.Reader, defaultGroup)

		if err != nil {
			panic(err)
		}

		peer.PrivKey = privkey
		reply = true
	}

	peer.PubKey = &data.Key
	peer.Secret = peer.PubKey.ComputeSecret(peer.PrivKey)
	peer.Key = peer.Secret.DeriveKey(sha256.New, 32, keyInfo)
	peer.MacLen = sha256.New().Size()
	peer.MacKey = peer.Secret.DeriveKey(sha256.New, peer.MacLen, macInfo)

	peer.Block, err = aes.NewCipher(peer.Key)

	if err != nil {
		panic(err)
	}

	peer.IV = peer.Secret.DeriveKey(sha256.New, peer.Block.BlockSize(), IVkeyInfo)
	peer.Stream = cipher.NewCTR(peer.Block, peer.IV)

	peer.Negotiated = true

	return reply
}

func (peer *Peer) Encrypt(dst, src []byte) []byte {
	var seq [4]byte
	binary.BigEndian.PutUint32(seq[:], peer.SeqOut)

	mac := hmac.New(sha256.New, peer.MacKey)

	mac.Write(seq[:])
	mac.Write(src)

	om := mac.Sum(nil)

	copy(dst, om)

	peer.Stream.XORKeyStream(dst[len(om):], src)

	peer.SeqOut++
	return dst
}

func (peer *Peer) Decrypt(data []byte) []byte {
	mac := hmac.New(sha256.New, peer.MacKey)

	payload := data[mac.Size():]

	peer.Stream.XORKeyStream(payload, payload)

	var seq [4]byte
	binary.BigEndian.PutUint32(seq[:], peer.SeqIn)

	mac.Write(seq[:])
	mac.Write(payload)

	om := mac.Sum(nil)

	check := data[:mac.Size()]

	peer.SeqIn++

	if !bytes.Equal(om, check) {
		return nil
	}

	return payload
}

var deviceName = flag.String("device", "tap0", "device name to create")
var peerArg = flag.String("peer", "", "peer to connect to")
var ipArg = flag.String("ip", "", "IP to assign to device")

func main() {
	flag.Parse()

	tun, err := tuntap.Open(*deviceName, tuntap.DevTap)
	if err != nil {
		fmt.Println("Error opening tun/tap device:", err)
		return
	}

	if len(*ipArg) > 0 {
		fmt.Printf("ip=%s, dev=%s\n", *ipArg, tun.Name())

		cmd := exec.Command("ip", "link", "set", *deviceName, "up")
		err = cmd.Run()

		if err != nil {
			panic(err)
		}

		cmd = exec.Command("ip", "addr", "add", *ipArg, "dev", *deviceName)
		err = cmd.Run()

		if err != nil {
			panic(err)
		}

		fmt.Printf("Listening on %s as %s\n", tun.Name(), *ipArg)
	} else {
		fmt.Println("Listening on", tun.Name())
	}

	proc := make(chan *Frame)

	Addr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:8000")

	if err != nil {
		panic("DISCO")
	}

	Conn, err := net.ListenUDP("udp4", Addr)

	go ReadUDP(Conn, proc)

	peers := make(Peers)

	if len(*peerArg) > 0 {
		addr, err := net.ResolveUDPAddr("udp4", *peerArg)

		if err != nil {
			panic("Unable to resolve host")
		}

		peer := new(Peer)
		peer.Addr = addr
		peer.Negotiated = false

		peers[addr.String()] = peer

		Conn.WriteMsgUDP(makeNegotiate(peer), nil, addr)
	}

	fmt.Println("Going into frame processing loop\n")

	go ReadDevice(tun, proc)

	for {
		frame := <-proc

		if frame.Input {
			peer, ok := peers[frame.From.String()]

			if !ok {
				fmt.Println("New peer!")
				peer = new(Peer)
				peer.Addr = frame.From
				peer.Negotiated = false

				peers[frame.From.String()] = peer
			}

			switch frame.Data[0] {
			case 0:
				// Negotiate
				if readNegotiate(frame, peer) {
					Conn.WriteMsgUDP(makeNegotiate(peer), nil, frame.From)
				}
			case 1:
				// Data

				pkt := tuntap.Packet{}
				pkt.Protocol = 0x8000
				pkt.Truncated = false

				pkt.Packet = peer.Decrypt(frame.Data[1:])

				if pkt.Packet != nil {
					tun.WritePacket(&pkt)
				} else {
					fmt.Println("Failed to decrypt and authenticated packet")
				}
			default:
				fmt.Printf("Invalid command: %x\n", frame.Data[0])
			}

		} else if len(peers) > 0 {
			for _, peer := range peers {
				if !peer.Negotiated {
					continue
				}

				buf := make([]byte, len(frame.Data)+peer.MacLen+1)
				buf[0] = 1
				peer.Encrypt(buf[1:], frame.Data)

				Conn.WriteMsgUDP(buf, nil, peer.Addr)
			}
		} else {
			fmt.Println("No one to send these frames to!")
		}
	}

}
