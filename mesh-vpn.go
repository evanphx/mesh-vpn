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
	"strings"
)

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

	var keyData []byte

	if len(*keyFile) > 0 {
		keyData, err = ioutil.ReadFile(*keyFile)
	}

	Addr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:8000")

	if err != nil {
		panic("DISCO")
	}

	Conn, err := net.ListenUDP("udp4", Addr)

	var s Server
	s.Conn = Conn
	s.keyData = keyData
	s.iface = iface
	s.tun = tun
	s.tap = &TapConsumer{tun, localKey}

	if len(*peerArg) > 0 {
		addr, err := net.ResolveUDPAddr("udp4", *peerArg)

		if err != nil {
			panic("Unable to resolve host")
		}

		s.peers = make(Peers)

		peer := s.NewPeer(addr)
		peer.Initiated = true

		peer.startNegotiate(Conn)
	}

	if len(*peersFile) > 0 {
		s.peers = readPeers(Conn)
	} else if s.peers == nil {
		s.peers = make(Peers)
	}

	s.Serve()
}
