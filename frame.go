package main

import (
	"encoding/binary"
	"errors"
	"net"
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

type RouteKey [6]byte

func (eth *Ethernet) DecodeFromBytes(data []byte) error {
	if len(data) < 14 {
		return errors.New("Ethernet packet too small")
	}

	eth.DstMAC = net.HardwareAddr(data[0:6])
	eth.SrcMAC = net.HardwareAddr(data[6:12])
	eth.Length = binary.BigEndian.Uint16(data[12:14])

	return nil
}

func (frame *Frame) DestKey() RouteKey {
	var key [6]byte
	copy(key[:], frame.Data[0:6])

	return (RouteKey)(key)
}

func DestKey(data []byte) RouteKey {
	var key [6]byte
	copy(key[:], data[0:6])

	return (RouteKey)(key)
}

func SrcKey(data []byte) RouteKey {
	var key [6]byte
	copy(key[:], data[6:12])

	return (RouteKey)(key)
}

func (key RouteKey) String() string {
	return net.HardwareAddr(key[:]).String()
}
