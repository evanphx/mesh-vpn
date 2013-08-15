package main

import (
	"code.google.com/p/tuntap"
)

type PacketConsumer interface {
	Send(data []byte) error
	Key() RouteKey
	Active() bool
}

type TapConsumer struct {
	tun *tuntap.Interface
	key RouteKey
}

func (tap *TapConsumer) Send(data []byte) error {
	pkt := tuntap.Packet{}
	pkt.Protocol = 0x8000
	pkt.Truncated = false

	pkt.Packet = data

	return tap.tun.WritePacket(&pkt)
}

func (tap *TapConsumer) Key() RouteKey {
	return tap.key
}

func (tap *TapConsumer) Active() bool {
	return true
}
