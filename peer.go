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

	Block  cipher.Block
	Stream cipher.Stream

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
