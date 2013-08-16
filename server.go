package main

import (
	"bytes"
	"code.google.com/p/tuntap"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var cPingData = []byte("mesh-vpn ping data")

type RouteMap map[RouteKey]*Peer

type Server struct {
	peers       Peers
	Conn        *net.UDPConn
	tun         *tuntap.Interface
	keyData     []byte
	iface       *net.Interface
	tap         *TapConsumer
	deadChannel chan *Peer
	routes      RouteMap
}

func (s *Server) HandleData(peer *Peer, frame *Frame) {
	if !peer.Authenticated {
		Debugf(dInfo, "Peer %s sent data without authentication", peer.String())
		s.sendGTFO(peer)
		return
	}

	data := peer.Decrypt(frame.Data[1:])

	if data != nil {
		if len(data) >= 14 {
			routeKey := SrcKey(data)

			if Debug {
				if _, ok := s.routes[routeKey]; !ok {
					Debugf(dConn, "Peer %s now owns %s", peer.String(),
						routeKey.String())
				}
			}

			s.routes[routeKey] = peer

			dk := DestKey(data)

			Debugf(dPacket, "Received packet for %s", dk.String())

			if bytes.Equal(dk[:], s.iface.HardwareAddr) {
				Debugf(dPacket, "Sending packet for self to tap")
				s.tap.Send(data)
			} else {
				if opeer, ok := s.routes[dk]; ok {
					Debugf(dPacket, "Re-routing incoming packet")

					opeer.Send(data)
				} else {
					Debugf(dPacket, "Flooding packet for unknown location")

					s.tap.Send(data)

					s.peers.Flood(data, peer)
				}
			}
		} else {
			Debugf(dInfo, "Too small packet detected")
		}
	} else {
		Debugf(dInfo, "Failed to decrypt and authenticated packet")
		s.sendGTFO(peer)
	}
}

func (s *Server) NewPeer(addr *net.UDPAddr) *Peer {
	peer := new(Peer)
	peer.Conn = s.Conn
	peer.Addr = addr

	s.peers[addr.String()] = peer

	return peer
}

func (s *Server) Peer(addr *net.UDPAddr) *Peer {
	peer, ok := s.peers[addr.String()]

	if !ok {
		Debugf(dConn, "New peer!")
		peer = s.NewPeer(addr)
	}

	return peer
}

func (s *Server) pruneRoutes(peer *Peer) {
	var toRemove []RouteKey

	for key, tpeer := range s.routes {
		if peer == tpeer {
			toRemove = append(toRemove, key)
		}
	}

	for _, key := range toRemove {
		delete(s.routes, key)
	}
}

func (s *Server) sendGTFO(peer *Peer) {
	peer.PrivKey = nil

	var buf [1]byte
	buf[0] = 2

	s.Conn.WriteMsgUDP(buf[:], nil, peer.Addr)
}

func (s *Server) HandleFrame(frame *Frame) {
	if frame.Input {
		peer := s.Peer(frame.From)

		peer.PacketsRecv++

		Debugf(dPacket, "Received data from %s", peer.String())

		switch frame.Data[0] {
		case 0:
			// Negotiate
			if peer.readNegotiate(frame) {
				peer.sendNegotiate()
			}

			if len(s.keyData) > 0 {
				peer.sendAuth(s.keyData)
			} else {
				Debugf(dInfo, "No key data, peer %s auto-authenticated", peer.String())
				peer.Authenticated = true
				peer.startPingTimer(s.deadChannel)
			}
		case 1:
			// Data
			s.HandleData(peer, frame)

		case 2:
			// GTFO
			Debugf(dConn, "Received GTFO from %s, restarting peering", peer.String())
			s.pruneRoutes(peer)

			peer.PrivKey = nil
			peer.Negotiated = false
			peer.Authenticated = false
			peer.stopPingTimer()
			peer.startNegotiate(s.Conn)

		case 3:
			// Auth

			data := peer.Decrypt(frame.Data[1:])

			if data == nil {
				Debugf(dInfo, "Auth with %s failed decryption", peer.String())
				s.sendGTFO(peer)
			} else if bytes.Equal(data, s.keyData) {
				peer.Authenticated = true
				peer.startPingTimer(s.deadChannel)
				Debugf(dInfo, "Peer %s authenticated and mesh'd", peer.String())

				if !peer.SentAuth {
					peer.sendAuth(s.keyData)
				}
			} else {
				Debugf(dPacket, "auth: %x, need: %x", data, s.keyData)
				Debugf(dInfo, "Peer %s presented invalid auth data", peer.String())
				s.sendGTFO(peer)
			}
		case 4:
			// Ping

			data := peer.Decrypt(frame.Data[1:])

			if data == nil {
				Debugf(dInfo, "Ping failed decryption")
				s.sendGTFO(peer)
			} else if bytes.Equal(data, cPingData) {
				Debugf(dPacket, "Ping checked successfully")
			} else {
				Debugf(dPacket, "Ping failed to decrypt")
			}

			s.Conn.WriteMsgUDP(peer.Encrypt(cPingData, 5), nil, frame.From)

		case 5:
			// Pong

			data := peer.Decrypt(frame.Data[1:])

			if data == nil {
				Debugf(dInfo, "Pong failed decryption")
				s.sendGTFO(peer)
			} else if bytes.Equal(data, cPingData) {
				Debugf(dPacket, "Pong checked successfully")
			} else {
				Debugf(dPacket, "Pong failed to decrypt")
			}

		default:
			fmt.Printf("Invalid command: %x\n", frame.Data[0])
		}

	} else if len(s.peers) > 0 {
		routingKey := frame.DestKey()

		if peer, ok := s.routes[routingKey]; ok {
			Debugf(dPacket, "Sending packet directly to %s", peer.String())
			peer.Send(frame.Data)
		} else {
			s.peers.Flood(frame.Data, nil)
		}
	}
}

func (s *Server) ReadUDP(proc chan *Frame) {
	for {
		buf := make([]byte, 10000)
		count, addr, _ := s.Conn.ReadFromUDP(buf)

		proc <- &Frame{true, addr, buf[0:count]}
	}
}

func (s *Server) ReadDevice(proc chan *Frame) {
	for {
		pkt, err := s.tun.ReadPacket()
		if err == nil {
			proc <- &Frame{false, nil, pkt.Packet}
		}
	}
}

func (s *Server) stopAllTimers() {
	for _, peer := range s.peers {
		s.pruneRoutes(peer)

		peer.stopPingTimer()
	}
}
func (s *Server) Serve() {
	hupChannel := make(chan os.Signal, 1)
	signal.Notify(hupChannel, syscall.SIGHUP)

	s.deadChannel = make(chan *Peer)
	proc := make(chan *Frame)

	go s.ReadUDP(proc)

	go s.ReadDevice(proc)

	s.routes = make(RouteMap)

	Debugf(dInfo, "Processing frames...")

	for {
		select {
		case <-hupChannel:
			if len(*peersFile) > 0 {
				Debugf(dInfo, "Reread peer list from file")
				s.stopAllTimers()
				s.peers = readPeers(s.Conn)
			}

		case peer := <-s.deadChannel:
			if peer.Initiated {
				Debugf(dInfo, "Detecte %s as dead peer, starting nego", peer.String())

				s.pruneRoutes(peer)

				peer.PrivKey = nil
				peer.Negotiated = false
				peer.Authenticated = false
				peer.startNegotiate(s.Conn)
			} else {
				Debugf(dInfo, "Detected %s as a dead peer, removing", peer.String())

				s.sendGTFO(peer)
				delete(s.peers, peer.Addr.String())
			}

		case frame := <-proc:
			s.HandleFrame(frame)
		}
	}

}
