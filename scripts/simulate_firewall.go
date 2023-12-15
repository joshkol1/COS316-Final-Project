package main

import (
	"flag"
	"fmt"
	"COS316-Final-Project/iptables-clone/tables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"os"
)

func main() {
	var rules_file_name string
	var pcap_file_name string
	var output_file_name string

	flag.StringVar(&rules_file_name, "rules", "iptables-clone.rules", "rules file to simulate")
	flag.StringVar(&pcap_file_name, "pcap", "", "pcap file to simulate")
	flag.StringVar(&output_file_name, "output", "output.txt", "file with decision for each packet")
	flag.Parse()

	// pcap is necessary. rules file defaults to iptables-clone.rules, output defaults to output.txt
	if pcap_file_name == "" {
		flag.PrintDefaults()
		return
	}

	table := tables.NewTable()
	table.LoadRules(rules_file_name)

	output_file, err := os.Create(output_file_name)
	if err != nil {
		panic(err)
	}
	defer output_file.Close()

	if handle, err := pcap.OpenOffline(pcap_file_name); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			decision := table.ProcessChain(table.GetChainByName("INPUT"), packet)
			_, write_err := output_file.WriteString(decision+"\n")
			if write_err != nil {
				panic(write_err)
			}
		}
	}
	fmt.Println("Wrote packet decisions to", output_file_name)
}