package main

import (
	"fmt"
	"log"
	"os"
	"net"
	"encoding/binary"
	// "github.com/google/gopacket"
	// "github.com/google/gopacket/pcap"
)

type NetFlowV5Template struct {
	version	uint16
	count uint16
	sysUpTime uint32
	unixSec uint32
	unixNSec uint32
	flowSec uint32
	engineType uint8
	engineID uint8
	samplInterval uint16
}

type NetFlowV9Template struct {
	version	uint16
	count uint16
	sysUpTime uint32
	unixSec uint32
	seqNumber uint32
	sourceID uint32
	NetFlowFlowset []NetFlowFlowset
}

type NetFlowFlowset struct {
	flowSetId   uint16
	flowSetLength	uint16
	flowRecords flowRecords
}

type flowRecords interface{}

type NetFlowTemplate256 struct {
	LAST_SWITCHED uint32
	FIRST_SWITCHED uint32
	PKTS uint64
	BYTES uint64
	INPUT_SNMP uint32
	OUTPUT_SNMP uint32
	IP_SRC_ADDR uint32
	IP_DST_ADDR uint32
}

const (
	listenPort = ":2055"
)

func main() {
	// Открываем UDP-порт для получения пакетов
	addr, err := net.ResolveUDPAddr("udp", listenPort)
	fmt.Println(addr)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("NetFlow Collector is listening on", listenPort)

	buf := make([]byte, 65535) // Буфер для чтения пакетов
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Received packet from %s, length: %d bytes\n", addr, n)

		// Обработка NetFlow пакета (здесь будет парсинг)
		template := parseNetFlowPacketHeader(buf[:n])

		// Используем type switch для обработки разных типов
		switch t := template.(type) {
		case NetFlowV9Template:
			fmt.Printf("Version: %d\n", t.version)
			fmt.Printf("Count: %d\n", t.count)
			fmt.Printf("SysUpTime: %d\n", t.sysUpTime)
			fmt.Printf("UnixSec: %d\n", t.unixSec)
			fmt.Printf("SeqNumber: %d\n", t.seqNumber)
			fmt.Printf("SourceID: %d\n", t.sourceID)
			for _, flowset := range t.NetFlowFlowset {

				k := 1

				fmt.Printf("### FlowSet %d ###\n", k)

				k++

				fmt.Printf("FlowSetId: %d\n", flowset.flowSetId)
				fmt.Printf("FlowSetLength: %d\n", flowset.flowSetLength)

				// Проверяем, что flowRecords содержит NetFlowTemplate256
				if template256, ok := flowset.flowRecords.(NetFlowTemplate256); ok {
					fmt.Printf("LAST_SWITCHED: %d\n", template256.LAST_SWITCHED)
					fmt.Printf("FIRST_SWITCHED: %d\n", template256.FIRST_SWITCHED)
					fmt.Printf("PKTS: %d\n", template256.PKTS)
					fmt.Printf("BYTES: %d\n", template256.BYTES)
					fmt.Printf("INPUT_SNMP: %d\n", template256.INPUT_SNMP)
					fmt.Printf("OUTPUT_SNMP: %d\n", template256.OUTPUT_SNMP)
					fmt.Printf("IP_SRC_ADDR: %d\n", template256.IP_SRC_ADDR)
					fmt.Printf("IP_DST_ADDR: %d\n", template256.IP_DST_ADDR)
				}
			}

		case NetFlowV5Template:
			fmt.Printf("Version: %d\n", t.version)
			fmt.Printf("Count: %d\n", t.count)
			fmt.Printf("System Uptime: %d\n", t.sysUpTime)
			fmt.Printf("Unix Seconds: %d\n", t.unixSec)
			fmt.Printf("Unix Nanoseconds: %d\n", t.unixNSec)
			fmt.Printf("Flow Seconds: %d\n", t.flowSec)
			fmt.Printf("Engine Type: %d\n", t.engineType)
			fmt.Printf("Engine ID: %d\n", t.engineID)
			fmt.Printf("Sample Interval: %d\n", t.samplInterval)
		default:
			fmt.Println("Unknown template")
		}
	}
}

// Пример простого парсинга NetFlow пакета (зависит от версии)
func parseNetFlowPacketHeader(packet []byte) interface{} {
	version := binary.BigEndian.Uint16(packet[0:2])

	if version == 9 {

		count  := binary.BigEndian.Uint16(packet[2:4])
		sysUpTime := binary.BigEndian.Uint32(packet[4:8])
		unixSec := binary.BigEndian.Uint32(packet[8:12])
		seqNumber := binary.BigEndian.Uint32(packet[12:16])
		sourceID := binary.BigEndian.Uint32(packet[16:20])

		flowsets := ParseNetFlowSets(packet[20:])

		template := NetFlowV9Template{
			version:   version,
			count:     count,
			sysUpTime: sysUpTime,
			unixSec:   unixSec,
			seqNumber: seqNumber,
			sourceID:  sourceID,
			NetFlowFlowset: flowsets,
		}
		return template

	} else if version == 5 {

		count  := binary.BigEndian.Uint16(packet[2:4])
		sysUpTime := binary.BigEndian.Uint32(packet[4:8])
		unixSec := binary.BigEndian.Uint32(packet[8:12])
		unixNSec := binary.BigEndian.Uint32(packet[12:16])
		flowSec := binary.BigEndian.Uint32(packet[16:20])
		engineType := uint8(packet[20])
		engineID := uint8(packet[21])
		samplInterval := binary.BigEndian.Uint16(packet[22:24])


		template := NetFlowV5Template{
			version:   version,
			count:     count,
			sysUpTime: sysUpTime,
			unixSec:   unixSec,
			unixNSec: unixNSec,
			flowSec: flowSec,
			engineType: engineType,
			engineID: engineID,
			samplInterval: samplInterval,
		}
		return template
	}
	return nil
}

// Функция для парсинга FlowSet
func ParseNetFlowSets(flowSets []byte) []NetFlowFlowset {

	flowSets_length := uint16(len(flowSets))

	var flowSetId uint16
    var flowSetLength uint16
	var flowSetsList []NetFlowFlowset
	var flowRecords flowRecords

	for {

		if flowSets_length > 0 {

			flowSetId = binary.BigEndian.Uint16(flowSets[0:2])
			flowSetLength = binary.BigEndian.Uint16(flowSets[2:4])

			if flowSetId == 256 {
				LAST_SWITCHED := binary.BigEndian.Uint32(flowSets[4:8])
				FIRST_SWITCHED := binary.BigEndian.Uint32(flowSets[8:12])
				PKTS := binary.BigEndian.Uint64(flowSets[12:20])
				BYTES := binary.BigEndian.Uint64(flowSets[20:28])
				INPUT_SNMP := binary.BigEndian.Uint32(flowSets[28:32])
				OUTPUT_SNMP := binary.BigEndian.Uint32(flowSets[32:36])
				IP_SRC_ADDR := binary.BigEndian.Uint32(flowSets[36:40])
				IP_DST_ADDR := binary.BigEndian.Uint32(flowSets[40:44])

				netFlowTemplate256 := NetFlowTemplate256 {
					LAST_SWITCHED: LAST_SWITCHED,
					FIRST_SWITCHED: FIRST_SWITCHED,
					PKTS: PKTS,
					BYTES: BYTES,
					INPUT_SNMP: INPUT_SNMP,
					OUTPUT_SNMP: OUTPUT_SNMP,
					IP_SRC_ADDR: IP_SRC_ADDR,
					IP_DST_ADDR: IP_DST_ADDR,
				}

				flowRecords = netFlowTemplate256
			} else {
				flowRecords = nil
			}

			flowSetsList = append(flowSetsList, NetFlowFlowset{
				flowSetId:    flowSetId,
				flowSetLength: flowSetLength,
				flowRecords:  flowRecords,
			})


			flowSets_length -= flowSetLength

			flowSets = flowSets[flowSetLength:]

		} else {
			break
		}

	}

	return flowSetsList

}