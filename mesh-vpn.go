package main

import (
  "fmt"
  "os"
  "net"
  "errors"
  "encoding/binary"
  "code.google.com/p/tuntap"
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
  From *net.UDPAddr
  Data []byte
}

type Peer struct {
  Addr *net.UDPAddr
}

type Peers map[string]Peer

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

    proc <- &Frame { true, addr, buf[0:count] }
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

      proc <- &Frame { false, nil, pkt.Packet }
    }
  }
}

func main() {
  fmt.Printf("hello here\n")

  if len(os.Args) < 3 {
    fmt.Println("syntax:", os.Args[0], "tun|tap", "<device name>", "<port>")
    return
  }

  var typ tuntap.DevKind
  switch os.Args[1] {
  case "tun":
    typ = tuntap.DevTun
  case "tap":
    typ = tuntap.DevTap
  default:
    fmt.Println("Unknown device type", os.Args[1])
    return
  }

  tun, err := tuntap.Open(os.Args[2], typ)
  if err != nil {
    fmt.Println("Error opening tun/tap device:", err)
    return
  }

  fmt.Println("Listening on", tun.Name())

  proc := make(chan *Frame)

  Addr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:8000")

  if err != nil {
    panic("DISCO")
  }

  Conn, err := net.ListenUDP("udp4", Addr)

  go ReadUDP(Conn, proc)

  peers := make(Peers)

  if len(os.Args) == 4 {
    Port := os.Args[3]

    addr, err := net.ResolveUDPAddr("udp4", Port)

    if err != nil {
      panic("Unable to resolve host")
    }

    peers[addr.String()] = Peer { addr }
  }

  fmt.Println("Going into frame processing loop\n")

  go ReadDevice(tun, proc)

  for {
    frame := <- proc

    if frame.Input {
      _, ok := peers[frame.From.String()]

      if !ok {
        fmt.Println("New peer!")
        peers[frame.From.String()] = Peer { frame.From }
      }

      pkt := tuntap.Packet{}
      pkt.Protocol = 0x8000
      pkt.Truncated = false
      pkt.Packet = frame.Data

      tun.WritePacket(&pkt)
    } else if len(peers) > 0 {
      for _, peer := range peers {
        Conn.WriteMsgUDP(frame.Data, nil, peer.Addr)
      }
    } else {
      fmt.Println("No one to send these frames to!")
    }
  }

}
