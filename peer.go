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
	Addr *net.UDPAddr

	NegotiationTimer *time.Timer
	Negotiated       bool

	PrivKey *dh.PrivateKey
	PubKey  *dh.SlimPublicKey
	Secret  *dh.Secret

	Key, IV []byte
	MacKey  []byte
	MacLen  int

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

	peer.IIV = dup(peer.IV)
	peer.OIV = dup(peer.IV)

	peer.Negotiated = true

	return reply
}

func (peer *Peer) Encrypt(src []byte) []byte {
	dst := make([]byte, 1+peer.MacLen+4+len(src))
	dst[0] = 1

	payload := dst[1+peer.MacLen:]

	binary.BigEndian.PutUint32(payload, peer.SeqOut)

	stream := cipher.NewCTR(peer.Block, peer.OIV)

	// h := sha256.New()
	// h.Write(src)

	// Debugf("enc: %x", h.Sum(nil))

	stream.XORKeyStream(payload[4:], src)

	mac := hmac.New(sha256.New, peer.MacKey)

	mac.Write(payload)

	om := mac.Sum(nil)

	copy(dst[1:], om)

	peer.SeqOut++

	inc(peer.OIV)

	return dst
}

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

	Debugf("pseq: %d, iseq: %d", seq, peer.SeqIn)

	if seq > peer.SeqIn {
		if seq < peer.SeqIn+10 {
			Debugf("Packet loss detected within window, winding")
			for j := uint32(0); j < seq-peer.SeqIn; j++ {
				inc(peer.IIV)
			}

			peer.SeqIn = seq
		} else {
			Debugf("Packet loss detected outside window!")
		}
	}

	stream := cipher.NewCTR(peer.Block, peer.IIV)

	stream.XORKeyStream(payload[4:], payload[4:])

	// h := sha256.New()
	// h.Write(payload[4:])

	// Debugf("dec: %x", h.Sum(nil))

	peer.SeqIn++

	inc(peer.IIV)

	return payload[4:]
}
