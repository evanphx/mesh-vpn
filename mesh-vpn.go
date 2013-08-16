package main

import (
	"bytes"
	"code.google.com/p/tuntap"
	"crypto/sha1"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/beevik/ntp"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

type RouteMap map[RouteKey]*Peer

var Routes RouteMap

func ReadUDP(conn *net.UDPConn, proc chan *Frame) {
	for {
		buf := make([]byte, 10000)
		count, addr, _ := conn.ReadFromUDP(buf)

		proc <- &Frame{true, addr, buf[0:count]}
	}
}

func ReadDevice(tun *tuntap.Interface, proc chan *Frame) {
	for {
		pkt, err := tun.ReadPacket()
		if err == nil {
			proc <- &Frame{false, nil, pkt.Packet}
		}
	}
}

func pruneRoutes(routes RouteMap, peer *Peer) {
	var toRemove []RouteKey

	for key, tpeer := range routes {
		if peer == tpeer {
			toRemove = append(toRemove, key)
		}
	}

	for _, key := range toRemove {
		delete(routes, key)
	}
}

func sendGTFO(conn *net.UDPConn, peer *Peer) {
	peer.PrivKey = nil

	var buf [1]byte
	buf[0] = 2

	conn.WriteMsgUDP(buf[:], nil, peer.Addr)
}

var cPingData = []byte("mesh-vpn ping data")

var keyInfo = []byte("diffie-hellman-group14-sha256-mesh-vpn")
var IVkeyInfo = []byte("diffie-hellman-group14-sha256-mesh-vpn-IV")
var macInfo = []byte("diffie-hellman-group14-sha256-mesh-vpn-mac")

var deviceName = flag.String("device", "tap0", "device name to create")
var peerArg = flag.String("peer", "", "peer to connect to")
var peersFile = flag.String("peers", "", "file containing peers to connect to")
var ipArg = flag.String("ip", "", "IP to assign to device")
var keyFile = flag.String("key", "", "Authenticate peers against contents of file")
var verboseLevel = flag.Int("verbose", 1, "How verbose to be logging")
var pingTimerOpt = flag.Int("ping", 10, "How often to ping peers to keep current")
var setupOpt = flag.String("setup", "", "Setup the interface with the given mac address")
var ulagen = flag.Bool("ula-gen", false, "Generate an IPv6 ULA prefix")

func stopAllTimers(peers Peers) {
	for _, peer := range peers {
		pruneRoutes(Routes, peer)

		peer.stopPingTimer()
	}
}

func readPeers(conn *net.UDPConn) Peers {
	peers := make(Peers)

	data, err := ioutil.ReadFile(*peersFile)

	if err != nil {
		panic(err)
	}

	lines := bytes.Split(data, []byte("\n"))

	for _, r := range lines {
		if len(r) == 0 {
			continue
		}

		Debugf(dConn, "Starting peer '%s'", string(r))
		addr, err := net.ResolveUDPAddr("udp4", string(r))

		if err != nil {
			panic("Unable to resolve host")
		}

		peer := new(Peer)
		peer.Initiated = true
		peer.Conn = conn
		peer.Addr = addr
		peer.Negotiated = false

		peers[addr.String()] = peer

		peer.startNegotiate(conn)
	}

	return peers
}

func ip(args ...string) {
	if Debug {
		fmt.Printf("RUN: " + strings.Join(args, " ") + "\n")
	}

	cmd := exec.Command("ip", args...)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr

	err := cmd.Run()

	if err != nil {
		panic(err)
	}
}

func ULAGen() {
	ifaces, err := net.Interfaces()

	var addr net.HardwareAddr

	for _, i := range ifaces {
		if len(i.HardwareAddr) > 0 {
			addr = i.HardwareAddr
			break
		}
	}

	var eui64 [8]byte

	eui64[0] = addr[0] | (1 << 7)
	eui64[1] = addr[1]
	eui64[2] = addr[2]
	eui64[3] = 0xff
	eui64[4] = 0xfe
	eui64[5] = addr[3]
	eui64[6] = addr[4]
	eui64[7] = addr[5]

	t, err := ntp.Time("pool.ntp.org")

	if err != nil {
		panic(err)
	}

	h := sha1.New()
	var tb [8]byte

	binary.BigEndian.PutUint64(tb[:], uint64(t.UnixNano()))
	h.Write(tb[:])
	h.Write(eui64[:])

	x := h.Sum(nil)

	var ula [6]byte

	ula[0] = 0xfc | 1
	copy(ula[1:], x[0:5])

	fmt.Printf("%X%X:%X%X:%X%X\n", ula[0], ula[1], ula[2], ula[3], ula[4], ula[5])
}

func setup() {

	addr, err := net.ParseMAC(*setupOpt)

	if err != nil {
		panic(err)
	}

	var eui64 [8]byte

	eui64[0] = addr[0] | (1 << 7)
	eui64[1] = addr[1]
	eui64[2] = addr[2]
	eui64[3] = 0xff
	eui64[4] = 0xfe
	eui64[5] = addr[3]
	eui64[6] = addr[4]
	eui64[7] = addr[5]

	ipv6 := *ipArg + fmt.Sprintf("%X%X:%X%X:%X%X:%X%X/64",
		eui64[0], eui64[1], eui64[2], eui64[3], eui64[4],
		eui64[5], eui64[6], eui64[7])

	ip("tuntap", "add", "dev", *deviceName, "mode", "tap")
	ip("link", "set", "dev", *deviceName, "down")
	ip("link", "set", "dev", *deviceName, "address", *setupOpt)
	ip("addr", "add", ipv6, "dev", *deviceName)
	ip("link", "set", "dev", *deviceName, "up")
}

func checkFile(ptr *string) {
	str := *ptr

	if len(str) > 0 && str[0:1] == "@" {
		data, err := ioutil.ReadFile(str[1:])
		if err != nil {
			panic(err)
		}

		*ptr = strings.TrimSpace(string(data))
	}
}

func main() {
	flag.BoolVar(&Debug, "debug", false, "show debugging output")
	flag.Parse()

	if Debug {
		DebugLevel = *verboseLevel
	}

	Debugf(dInfo, "Debugging enabled")

	checkFile(ipArg)
	checkFile(setupOpt)

	if *ulagen {
		ULAGen()
		return
	}

	if len(*setupOpt) > 0 {
		setup()
		return
	}

	PingTimer = *pingTimerOpt

	tun, err := tuntap.Open(*deviceName, tuntap.DevTap)
	if err != nil {
		fmt.Println("Error opening tun/tap device:", err)
		return
	}

	if len(*ipArg) > 0 {
		ip("link", "set", *deviceName, "ip")
		ip("addr", "add", *ipArg, "dev", *deviceName)

		fmt.Printf("Listening on %s as %s\n", tun.Name(), *ipArg)
	} else {
		fmt.Println("Listening on", tun.Name())
	}

	iface, err := net.InterfaceByName(*deviceName)

	if err != nil {
		ifaces, err := net.Interfaces()

		for _, i := range ifaces {
			fmt.Printf("%d: %s %s\n", i.Index, i.Name, i.HardwareAddr.String())
		}

		panic(fmt.Sprintf("Error opening '%s': %s", tun.Name(), err))
	}

	var localKey RouteKey
	copy(localKey[:], iface.HardwareAddr)

	tap := TapConsumer{tun, localKey}

	var keyData []byte

	if len(*keyFile) > 0 {
		keyData, err = ioutil.ReadFile(*keyFile)
	}

	proc := make(chan *Frame)

	Addr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:8000")

	if err != nil {
		panic("DISCO")
	}

	Conn, err := net.ListenUDP("udp4", Addr)

	var peers Peers

	if len(*peerArg) > 0 {
		addr, err := net.ResolveUDPAddr("udp4", *peerArg)

		if err != nil {
			panic("Unable to resolve host")
		}

		peers = make(Peers)

		peer := new(Peer)
		peer.Initiated = true
		peer.Conn = Conn
		peer.Addr = addr
		peer.Negotiated = false

		peers[addr.String()] = peer

		peer.startNegotiate(Conn)
	}

	if len(*peersFile) > 0 {
		peers = readPeers(Conn)
	} else if peers == nil {
		peers = make(Peers)
	}

	hupChannel := make(chan os.Signal, 1)
	signal.Notify(hupChannel, syscall.SIGHUP)

	deadChannel := make(chan *Peer)

	go ReadUDP(Conn, proc)

	go ReadDevice(tun, proc)

	Routes = make(RouteMap)

	Debugf(dInfo, "Processing frames...")

	for {
		select {
		case <-hupChannel:
			if len(*peersFile) > 0 {
				Debugf(dInfo, "Reread peer list from file")
				stopAllTimers(peers)
				peers = readPeers(Conn)
			}

		case peer := <-deadChannel:
			if peer.Initiated {
				Debugf(dInfo, "Detecte %s as dead peer, starting nego", peer.String())

				pruneRoutes(Routes, peer)

				peer.PrivKey = nil
				peer.Negotiated = false
				peer.Authenticated = false
				peer.startNegotiate(Conn)
			} else {
				Debugf(dInfo, "Detected %s as a dead peer, removing", peer.String())

				sendGTFO(Conn, peer)
				delete(peers, peer.Addr.String())
			}

		case frame := <-proc:

			if frame.Input {
				peer, ok := peers[frame.From.String()]

				if !ok {
					Debugf(dConn, "New peer!")
					peer = new(Peer)
					peer.Conn = Conn
					peer.Addr = frame.From
					peer.Negotiated = false

					peers[frame.From.String()] = peer
				}

				peer.PacketsRecv++

				Debugf(dPacket, "Received data from %s", peer.String())

				switch frame.Data[0] {
				case 0:
					// Negotiate
					if peer.readNegotiate(frame) {
						Conn.WriteMsgUDP(peer.makeNegotiate(), nil, frame.From)
					}

					if len(keyData) > 0 {
						peer.SentAuth = true
						Conn.WriteMsgUDP(peer.makeAuth(keyData), nil, frame.From)
					} else {
						Debugf(dInfo, "No key data, peer %s auto-authenticated", peer.String())
						peer.Authenticated = true
						peer.startPingTimer(deadChannel)
					}
				case 1:
					// Data

					if !peer.Authenticated {
						Debugf(dInfo, "Peer %s sent data without authentication", peer.String())
						sendGTFO(Conn, peer)
						continue
					}

					data := peer.Decrypt(frame.Data[1:])

					if data != nil {
						if len(data) >= 14 {
							routeKey := SrcKey(data)

							if Debug {
								if _, ok := Routes[routeKey]; !ok {
									Debugf(dConn, "Peer %s now owns %s", peer.String(),
										routeKey.String())
								}
							}

							Routes[routeKey] = peer

							dk := DestKey(data)

							Debugf(dPacket, "Received packet for %s", dk.String())

							if bytes.Equal(dk[:], iface.HardwareAddr) {
								Debugf(dPacket, "Sending packet for self to tap")
								tap.Send(data)
							} else {
								if opeer, ok := Routes[dk]; ok {
									Debugf(dPacket, "Re-routing incoming packet")

									opeer.Send(data)
								} else {
									Debugf(dPacket, "Flooding packet for unknown location")

									tap.Send(data)

									peers.Flood(data, peer)
								}
							}
						} else {
							Debugf(dInfo, "Too small packet detected")
						}
					} else {
						Debugf(dInfo, "Failed to decrypt and authenticated packet")
						sendGTFO(Conn, peer)
					}
				case 2:
					// GTFO
					Debugf(dConn, "Received GTFO from %s, restarting peering", peer.String())
					pruneRoutes(Routes, peer)

					peer.PrivKey = nil
					peer.Negotiated = false
					peer.Authenticated = false
					peer.stopPingTimer()
					peer.startNegotiate(Conn)

				case 3:
					// Auth

					data := peer.Decrypt(frame.Data[1:])

					if data == nil {
						Debugf(dInfo, "Auth with %s failed decryption", peer.String())
						sendGTFO(Conn, peer)
					} else if bytes.Equal(data, keyData) {
						peer.Authenticated = true
						peer.startPingTimer(deadChannel)
						Debugf(dInfo, "Peer %s authenticated and mesh'd", peer.String())

						if !peer.SentAuth {
							peer.SentAuth = true
							Conn.WriteMsgUDP(peer.makeAuth(keyData), nil, frame.From)
						}
					} else {
						Debugf(dPacket, "auth: %x, need: %x", data, keyData)
						Debugf(dInfo, "Peer %s presented invalid auth data", peer.String())
						sendGTFO(Conn, peer)
					}
				case 4:
					// Ping

					data := peer.Decrypt(frame.Data[1:])

					if data == nil {
						Debugf(dInfo, "Ping failed decryption")
						sendGTFO(Conn, peer)
					} else if bytes.Equal(data, cPingData) {
						Debugf(dPacket, "Ping checked successfully")
					} else {
						Debugf(dPacket, "Ping failed to decrypt")
					}

					Conn.WriteMsgUDP(peer.Encrypt(cPingData, 5), nil, frame.From)

				case 5:
					// Pong

					data := peer.Decrypt(frame.Data[1:])

					if data == nil {
						Debugf(dInfo, "Pong failed decryption")
						sendGTFO(Conn, peer)
					} else if bytes.Equal(data, cPingData) {
						Debugf(dPacket, "Pong checked successfully")
					} else {
						Debugf(dPacket, "Pong failed to decrypt")
					}

				default:
					fmt.Printf("Invalid command: %x\n", frame.Data[0])
				}

			} else if len(peers) > 0 {
				routingKey := frame.DestKey()

				if peer, ok := Routes[routingKey]; ok {
					Debugf(dPacket, "Sending packet directly to %s", peer.String())
					peer.Send(frame.Data)
				} else {
					peers.Flood(frame.Data, nil)
				}
			}
		}
	}
}
