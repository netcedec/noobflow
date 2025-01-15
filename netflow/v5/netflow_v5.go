package v5
import (
	"fmt"
	// "log"
	// "os"
	// "net"
	"encoding/binary"
)

// Netflow v5 header
type NetFlowV5Template struct {
	version	uint16
	count uint16
	sysUptime uint32
	unix_secs uint32
	unix_nsecs uint32
	flow_sequence uint32
	engine_type uint8
	engine_id uint8
	sampling_interval uint16
}

// Netflow v5 pdu
type NetFlowV5pdu struct {
	srcaddr uint32
	dstaddr uint32
	nexthop uint32
	input uint16
	output uint16
	dPkts uint32
	dOctets uint32
	First uint32
	Last uint32
	srcport uint16
	dstport uint16
	pad1 uint8
	tcp_flags uint8
	prot uint8
	tos uint8
	src_as uint16
	dst_as uint16
	src_mask uint8
	dst_mask uint8
	pad2 uint16
}

func ParseNetFlowV5(packet []byte, version uint16) {

	count  := binary.BigEndian.Uint16(packet[2:4])
	sysUptime := binary.BigEndian.Uint32(packet[4:8])
	unix_secs := binary.BigEndian.Uint32(packet[8:12])
	unix_nsecs := binary.BigEndian.Uint32(packet[12:16])
	flow_sequence := binary.BigEndian.Uint32(packet[16:20])
	engine_type := uint8(packet[20])
	engine_id := uint8(packet[21])
	sampling_interval := binary.BigEndian.Uint16(packet[22:24])

	t := NetFlowV5Template{
		version:   version,
		count:     count,
		sysUptime: sysUptime,
		unix_secs:   unix_secs,
		unix_nsecs: unix_nsecs,
		flow_sequence: flow_sequence,
		engine_type: engine_type,
		engine_id: engine_id,
		sampling_interval: sampling_interval,
	}

	fmt.Println("\n### NETFLOW V5 ###")
	fmt.Printf("Version: %d\n", t.version)
	fmt.Printf("Count: %d\n", t.count)
	fmt.Printf("System Uptime: %d\n", t.sysUptime)
	fmt.Printf("Unix Seconds: %d\n", t.unix_secs)
	fmt.Printf("Unix Nanoseconds: %d\n", t.unix_nsecs)
	fmt.Printf("Flow Seconds: %d\n", t.flow_sequence)
	fmt.Printf("Engine Type: %d\n", t.engine_type)
	fmt.Printf("Engine ID: %d\n", t.engine_id)
	fmt.Printf("Sample Interval: %d\n", t.sampling_interval)

	//v5 header = 24 byte
	//pdu = 48 byte

	for i :=0; i < int(count); i++ {
		pduStart := 24 + i*48

		pdu := NetFlowV5pdu {
			srcaddr:  binary.BigEndian.Uint32(packet[pduStart : pduStart+4]),
			dstaddr:  binary.BigEndian.Uint32(packet[pduStart+4 : pduStart+8]),
			nexthop:  binary.BigEndian.Uint32(packet[pduStart+8 : pduStart+12]),
			input:    binary.BigEndian.Uint16(packet[pduStart+12 : pduStart+14]),
			output:   binary.BigEndian.Uint16(packet[pduStart+14 : pduStart+16]),
			dPkts:    binary.BigEndian.Uint32(packet[pduStart+16 : pduStart+20]),
			dOctets:  binary.BigEndian.Uint32(packet[pduStart+20 : pduStart+24]),
			First:    binary.BigEndian.Uint32(packet[pduStart+24 : pduStart+28]),
			Last:     binary.BigEndian.Uint32(packet[pduStart+28 : pduStart+32]),
			srcport:  binary.BigEndian.Uint16(packet[pduStart+32 : pduStart+34]),
			dstport:  binary.BigEndian.Uint16(packet[pduStart+34 : pduStart+36]),
			pad1:     packet[pduStart+36],
			tcp_flags: packet[pduStart+37],
			prot:     packet[pduStart+38],
			tos:      packet[pduStart+39],
			src_as:   binary.BigEndian.Uint16(packet[pduStart+40 : pduStart+42]),
			dst_as:   binary.BigEndian.Uint16(packet[pduStart+42 : pduStart+44]),
			src_mask: packet[pduStart+44],
			dst_mask: packet[pduStart+45],
			pad2:     binary.BigEndian.Uint16(packet[pduStart+46 : pduStart+48]),
		}

		// Print pdu data
		fmt.Printf("PDU #%d:\n", i+1)
		fmt.Printf("  SrcAddr: %d\n", pdu.srcaddr)
		fmt.Printf("  DstAddr: %d\n", pdu.dstaddr)
		fmt.Printf("  NextHop: %d\n", pdu.nexthop)
		fmt.Printf("  Input: %d\n", pdu.input)
		fmt.Printf("  Output: %d\n", pdu.output)
		fmt.Printf("  dPkts: %d\n", pdu.dPkts)
		fmt.Printf("  dOctets: %d\n", pdu.dOctets)
		fmt.Printf("  First: %d\n", pdu.First)
		fmt.Printf("  Last: %d\n", pdu.Last)
		fmt.Printf("  SrcPort: %d\n", pdu.srcport)
		fmt.Printf("  DstPort: %d\n", pdu.dstport)
		fmt.Printf("  Pad1: %d\n", pdu.pad1)
		fmt.Printf("  TcpFlags: %d\n", pdu.tcp_flags)
		fmt.Printf("  Prot: %d\n", pdu.prot)
		fmt.Printf("  TOS: %d\n", pdu.tos)
		fmt.Printf("  SrcAS: %d\n", pdu.src_as)
		fmt.Printf("  DstAS: %d\n", pdu.dst_as)
		fmt.Printf("  SrcMask: %d\n", pdu.src_mask)
		fmt.Printf("  DstMask: %d\n", pdu.dst_mask)
		fmt.Printf("  Pad2: %d\n", pdu.pad2)
		fmt.Println()
	}

}
