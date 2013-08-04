package main

import (
	"code.google.com/p/tuntap"
	"flag"
	"fmt"
	"net"
	"os/exec"
)

type Peers map[string]*Peer
type Routes map[RouteKey]*Peer

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

var keyInfo = []byte("diffie-hellman-group14-sha256-mesh-vpn")
var IVkeyInfo = []byte("diffie-hellman-group14-sha256-mesh-vpn-IV")
var macInfo = []byte("diffie-hellman-group14-sha256-mesh-vpn-mac")

var deviceName = flag.String("device", "tap0", "device name to create")
var peerArg = flag.String("peer", "", "peer to connect to")
var ipArg = flag.String("ip", "", "IP to assign to device")

func main() {
	flag.BoolVar(&Debug, "debug", false, "show debugging output")
	flag.Parse()

	Debugf("Debugging enabled")

	tun, err := tuntap.Open(*deviceName, tuntap.DevTap)
	if err != nil {
		fmt.Println("Error opening tun/tap device:", err)
		return
	}

	if len(*ipArg) > 0 {
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

		peer.startNegotiate(Conn)
	}

	go ReadDevice(tun, proc)

	routes := make(Routes)

	Debugf("Processing frames...")

	for {
		frame := <-proc

		if frame.Input {
			peer, ok := peers[frame.From.String()]

			if !ok {
				Debugf("New peer!")
				peer = new(Peer)
				peer.Addr = frame.From
				peer.Negotiated = false

				peers[frame.From.String()] = peer
			}

			switch frame.Data[0] {
			case 0:
				// Negotiate
				if peer.readNegotiate(frame) {
					Conn.WriteMsgUDP(peer.makeNegotiate(), nil, frame.From)
				}
			case 1:
				// Data

				pkt := tuntap.Packet{}
				pkt.Protocol = 0x8000
				pkt.Truncated = false

				pkt.Packet = peer.Decrypt(frame.Data[1:])

				if pkt.Packet != nil {
					if len(pkt.Packet) >= 14 {
						routeKey := SrcKey(pkt.Packet)
						if Debug {
							if _, ok := routes[routeKey]; !ok {
								Debugf("Peer %s now owns %s", peer.String(),
									routeKey.String())
							}
						}

						routes[routeKey] = peer
						tun.WritePacket(&pkt)
					} else {
						Debugf("Too small packet detected")
					}
				} else {
					Debugf("Failed to decrypt and authenticated packet")
				}
			default:
				fmt.Printf("Invalid command: %x\n", frame.Data[0])
			}

		} else if len(peers) > 0 {
			routingKey := frame.DestKey()

			if peer, ok := routes[routingKey]; ok {
				buf := make([]byte, len(frame.Data)+peer.MacLen+1)
				buf[0] = 1
				peer.Encrypt(buf[1:], frame.Data)

				Conn.WriteMsgUDP(buf, nil, peer.Addr)
			} else {
				for _, peer := range peers {
					if !peer.Negotiated {
						continue
					}

					buf := make([]byte, len(frame.Data)+peer.MacLen+1)
					buf[0] = 1
					peer.Encrypt(buf[1:], frame.Data)

					Conn.WriteMsgUDP(buf, nil, peer.Addr)
				}
			}
		}
	}
}
