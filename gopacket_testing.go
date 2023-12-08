package main

import (
    "fmt"
    "log"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

/*
	Needed to run the following commands 
	go get github.com/google/gopacket
	go get github.com/google/gopacket/layers
	go get github.com/google/gopacket/pcap 
*/

func main() {
    // Open the .pcap file
    handle, err := pcap.OpenOffline("example.pcap")
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    // Loop through packets in file
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        printPacketInfo(packet)
    }
}

func printPacketInfo(packet gopacket.Packet) {
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