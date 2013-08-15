package main

import (
	"bytes"
	"code.google.com/p/tuntap"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

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

func sendGTFO(conn *net.UDPConn, peer *Peer) {
	peer.PrivKey = nil

	var buf [1]byte
	buf[0] = 2

	conn.WriteMsgUDP(buf[:], nil, peer.Addr)
}

var keyInfo = []byte("diffie-hellman-group14-sha256-mesh-vpn")
var IVkeyInfo = []byte("diffie-hellman-group14-sha256-mesh-vpn-IV")
var macInfo = []byte("diffie-hellman-group14-sha256-mesh-vpn-mac")

var deviceName = flag.String("device", "tap0", "device name to create")
var peerArg = flag.String("peer", "", "peer to connect to")
var peersFile = flag.String("peers", "", "file containing peers to connect to")
var ipArg = flag.String("ip", "", "IP to assign to device")
var keyFile = flag.String("key", "", "Authenticate peers against contents of file")
var verboseLevel = flag.Int("verbose", 1, "How verbose to be logging")

func readPeers(peers Peers, conn *net.UDPConn, prune bool) {
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
		peer.Conn = conn
		peer.Addr = addr
		peer.Negotiated = false

		peers[addr.String()] = peer

		peer.startNegotiate(conn)
	}
}

func main() {
	flag.BoolVar(&Debug, "debug", false, "show debugging output")
	flag.Parse()

	if Debug {
		DebugLevel = *verboseLevel
	}

	Debugf(dInfo, "Debugging enabled")

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

	peers := make(Peers)

	if len(*peerArg) > 0 {
		addr, err := net.ResolveUDPAddr("udp4", *peerArg)

		if err != nil {
			panic("Unable to resolve host")
		}

		peer := new(Peer)
		peer.Conn = Conn
		peer.Addr = addr
		peer.Negotiated = false

		peers[addr.String()] = peer

		peer.startNegotiate(Conn)
	}

	if len(*peersFile) > 0 {
		readPeers(peers, Conn, false)
	}

	hupChannel := make(chan os.Signal, 1)
	signal.Notify(hupChannel, syscall.SIGHUP)

	go ReadUDP(Conn, proc)

	go ReadDevice(tun, proc)

	routes := make(Routes)

	Debugf(dInfo, "Processing frames...")

	for {
		select {
		case <-hupChannel:
			Debugf(dInfo, "Reread peer list from file")
			readPeers(peers, Conn, false)

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
					}
				case 1:
					// Data

					data := peer.Decrypt(frame.Data[1:])

					if data != nil {
						if len(data) >= 14 {
							routeKey := SrcKey(data)

							if Debug {
								if _, ok := routes[routeKey]; !ok {
									Debugf(dConn, "Peer %s now owns %s", peer.String(),
										routeKey.String())
								}
							}

							routes[routeKey] = peer

							dk := DestKey(data)

							Debugf(dPacket, "Received packet for %s", dk.String())

							if bytes.Equal(dk[:], iface.HardwareAddr) {
								Debugf(dPacket, "Sending packet for self to tap")
								tap.Send(data)
							} else {
								if opeer, ok := routes[dk]; ok {
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
					peer.PrivKey = nil
					peer.Negotiated = false
					peer.Authenticated = false
					peer.startNegotiate(Conn)

				case 3:
					// Auth

					data := peer.Decrypt(frame.Data[1:])

					if bytes.Equal(data, keyData) {
						peer.Authenticated = true
						Debugf(dInfo, "Peer %s authenticated and mesh'd", peer.String())

						if !peer.SentAuth {
							peer.SentAuth = true
							Conn.WriteMsgUDP(peer.makeAuth(keyData), nil, frame.From)
						}
					} else {
						Debugf(dInfo, "Peer %s presented invalid auth data", peer.String())
					}
				default:
					fmt.Printf("Invalid command: %x\n", frame.Data[0])
				}

			} else if len(peers) > 0 {
				routingKey := frame.DestKey()

				if peer, ok := routes[routingKey]; ok {
					Debugf(dPacket, "Sending packet directly to %s", peer.String())
					peer.Send(frame.Data)
				} else {
					peers.Flood(frame.Data, nil)
				}
			}
		}
	}
}
