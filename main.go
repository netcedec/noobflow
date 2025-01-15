package main

import (
	"fmt"
	"log"
	"os"
	"net"
	"encoding/binary"
	"noobflow/netflow/v5"
	// "github.com/google/gopacket"
	// "github.com/google/gopacket/pcap"
)

const (
	listenPort = ":2055"
)

func main() {

	// UDP port 2055 all interface
	addr, err := net.ResolveUDPAddr("udp", listenPort)
	fmt.Println(addr)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	// Open UDP port for listen
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("NetFlow Collector is listening on", listenPort)

	// Buffer for packets
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Received packet from %s, length: %d bytes\n", addr, n)

		parseNetFlowPacketHeader(buf[:n])
	}
}

// Parse netflow packet
func parseNetFlowPacketHeader(packet []byte) {

	version := binary.BigEndian.Uint16(packet[0:2])

	if version == 5 {

		v5.ParseNetFlowV5(packet[:], version)

	} else {

		fmt.Printf("Version %d support is coming soon...", version)
	}

}