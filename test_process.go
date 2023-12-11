package main

import (
	"COS316-Final-Project/iptables-clone/tables"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func printInfo(packet gopacket.Packet) {
	// Print basic information about the packet
	fmt.Printf("Packet: %v\n", packet)

	// Check if the packet is an IP packet (IPv4)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
	}

	// Check if the packet is a TCP packet
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
	}

	fmt.Println("-----")
}

func main() {
	// create a new table
	testTable := tables.NewTable()
	// create new chains for the table
	chain1 := tables.NewChain()
	chain2 := tables.NewChain()
	chain3 := tables.NewChain()

	// set the default policy for some of the chains
	chain1.DefaultPolicy = "ACCEPT"
	chain3.DefaultPolicy = "DROP"

	// define the rules for each chain
	rule1 := tables.NewRule()
	rule1.SrcIP = "10.8.38.199"
	rule1.Action = "LOG"

	rule11 := tables.NewRule()
	rule11.DstIP = "1.2.3.4"
	rule11.Action = "JUMP"
	rule11.JumpChain = "chain2"

	rule2 := tables.NewRule()
	rule2.DstPort = "80"
	rule2.Action = "JUMP"
	rule2.JumpChain = "chain3"

	rule3 := tables.NewRule()
	rule3.SrcPort = "20"

	// insert the rules into the chains
	chain1.InsertAtIndex(rule1, 0)
	chain1.AppendRule(rule11)
	chain2.InsertAtIndex(rule2, 0)
	chain3.InsertAtIndex(rule3, 0)

	testTable.Chains["chain1"] = chain1
	testTable.Chains["chain2"] = chain2
	testTable.Chains["chain3"] = chain3

	handle, err := pcap.OpenOffline("test_packets/example.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		testTable.ProcessChain(*chain1, packet)
		// printInfo(packet)
		break
	}
}
