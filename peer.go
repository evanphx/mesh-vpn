package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"github.com/evanphx/go-crypto-dh/dh"
	"net"
	"time"
)

var defaultGroup = dh.Group14

type Peer struct {
	Conn *net.UDPConn
	Addr *net.UDPAddr

	RouteKey RouteKey

	NegotiationTimer *time.Timer
	Negotiated       bool
	SentNego         bool

	Authenticated bool
	SentAuth      bool

	PrivKey *dh.PrivateKey
	PubKey  *dh.SlimPublicKey
	Secret  *dh.Secret

	CryptoKey, CryptoIV []byte
	MacKey              []byte
	MacLen              int

	Block cipher.Block

	IIV, OIV []byte

	SeqIn, SeqOut uint32
}

func (peer *Peer) String() string {
	return peer.Addr.String()
}

type negotiationData struct {
	Key dh.SlimPublicKey
}

func (peer *Peer) startNegotiate(conn *net.UDPConn) {
	Debugf("Sending nego to %s", peer.Addr.String())

	conn.WriteMsgUDP(peer.makeNegotiate(), nil, peer.Addr)

	peer.SentNego = true

	d := time.Second * 3

	peer.NegotiationTimer = time.AfterFunc(d, func() {
		peer.startNegotiate(conn)
	})
}

func (peer *Peer) makeNegotiate() []byte {
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

func (peer *Peer) makeAuth(auth []byte) []byte {
	return peer.Encrypt(auth, 3)
}

func dup(p []byte) []byte {
	q := make([]byte, len(p))
	copy(q, p)
	return q
}

func inc(p []byte) {
	for i := 0; i < len(p); i++ {
		p[i]++

		if (p[i]) != 0 {
			break
		}
	}
}

func (peer *Peer) readNegotiate(frame *Frame) bool {
	var buf bytes.Buffer

	Debugf("Reading nego...")

	if peer.NegotiationTimer != nil {
		peer.NegotiationTimer.Stop()
		peer.NegotiationTimer = nil
	}

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

	// If we were already negotiated, then we're doing a re-nego, so
	// reply.
	if peer.Negotiated {
		reply = true
	}

	peer.PubKey = &data.Key
	peer.Secret = peer.PubKey.ComputeSecret(peer.PrivKey)
	peer.CryptoKey = peer.Secret.DeriveKey(sha256.New, 32, keyInfo)
	peer.MacLen = sha256.New().Size()
	peer.MacKey = peer.Secret.DeriveKey(sha256.New, peer.MacLen, macInfo)

	peer.Block, err = aes.NewCipher(peer.CryptoKey)

	if err != nil {
		panic(err)
	}

	peer.CryptoIV = peer.Secret.DeriveKey(sha256.New, peer.Block.BlockSize(), IVkeyInfo)

	peer.IIV = dup(peer.CryptoIV)
	peer.OIV = dup(peer.CryptoIV)

	peer.SeqIn = 0
	peer.SeqOut = 0

	peer.Negotiated = true
	Debugf("Peer %s negotiated", peer.String())

	return reply
}

func (peer *Peer) Encrypt(src []byte, cmd byte) []byte {
	dst := make([]byte, 1+peer.MacLen+4+len(src))
	dst[0] = cmd

	payload := dst[1+peer.MacLen:]

	binary.BigEndian.PutUint32(payload, peer.SeqOut)

	stream := cipher.NewCTR(peer.Block, peer.OIV)

	stream.XORKeyStream(payload[4:], src)

	mac := hmac.New(sha256.New, peer.MacKey)

	mac.Write(payload)

	om := mac.Sum(nil)

	copy(dst[1:], om)

	peer.SeqOut++

	inc(peer.OIV)

	return dst
}

const cWindow = 10

func (peer *Peer) Decrypt(data []byte) []byte {
	mac := hmac.New(sha256.New, peer.MacKey)

	payload := data[mac.Size():]

	mac.Write(payload)

	om := mac.Sum(nil)

	check := data[:mac.Size()]

	if !bytes.Equal(om, check) {
		Debugf("HMAC failed!")
		return nil
	}

	seq := binary.BigEndian.Uint32(payload)

	if seq > peer.SeqIn {
		if seq < peer.SeqIn+cWindow {
			Debugf("Packet loss detected within window, winding (%d != %d)",
				seq, peer.SeqIn)
			for j := uint32(0); j < seq-peer.SeqIn; j++ {
				inc(peer.IIV)
			}

			peer.SeqIn = seq
		} else {
			Debugf("Packet loss detected outside window!")
			return nil
		}
	}

	stream := cipher.NewCTR(peer.Block, peer.IIV)

	stream.XORKeyStream(payload[4:], payload[4:])

	peer.SeqIn++

	inc(peer.IIV)

	return payload[4:]
}

func (peer *Peer) Send(data []byte) error {
	peer.Conn.WriteMsgUDP(peer.Encrypt(data, 1), nil, peer.Addr)
	return nil
}

func (peer *Peer) Key() RouteKey {
	return peer.RouteKey
}

func (peer *Peer) Active() bool {
	return peer.Authenticated
}

type Peers map[string]*Peer

func (peers Peers) Flood(data []byte, src *Peer) {
	Debugf("Flooding data to peers")

	for _, peer := range peers {
		if peer != src && peer.Active() {
			Debugf("Flooding data to %s", peer.String())
			peer.Send(data)
		}
	}
}
