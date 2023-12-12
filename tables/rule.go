package tables

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Rule struct {
	ChainName    string // Name of the chain the rule is in
	Protocol     string // TCP, UDP, ICMP, etc.
	SrcIP        string // Source IP address
	SrcPort      string // Source port
	DstIP        string // Destination IP address
	DstPort      string // Destination port
	InInterface  string // Incoming interface
	OutInterface string // Outgoing interface
	Action       string // ACCEPT, DROP, JUMP
	JumpChain    string // Chain to jump to if action is JUMP
}

// Creates a new rule with the given parameters
func NewRule() *Rule {
	return &Rule{}
}

// Prints the rule
func (r *Rule) PrintRule() {
	fmt.Printf("%+v\n", r)
}

// Checks if the given rule matches the current rule
func (r *Rule) CheckMatch(otherRule Rule) bool {
	if r.Protocol != otherRule.Protocol {
		return false
	}
	if r.SrcIP != otherRule.SrcIP {
		return false
	}
	if r.SrcPort != otherRule.SrcPort {
		return false
	}
	if r.DstIP != otherRule.DstIP {
		return false
	}
	if r.DstPort != otherRule.DstPort {
		return false
	}
	if r.InInterface != otherRule.InInterface {
		return false
	}
	if r.OutInterface != otherRule.OutInterface {
		return false
	}

	if r.Action != otherRule.Action {
		return false
	}
	return true
}

func (r *Rule) GetAction() string {
	return r.Action
}

/*
THIS CURRENTLY ONLY IMPLEMENTS CHECKS FOR SOURCE AND DESTINATION IP AND PORT FOR TESTING.
STILL NEED TO ADD CHECKS FOR THE OTHER FIELDS
*/

// Checks if the given packet matches the rule
func (r *Rule) CheckPacketMatch(packet gopacket.Packet) bool {
	// Check Protocol
	if r.Protocol != "" {
		switch r.Protocol {
		case "TCP":
			if packet.Layer(layers.LayerTypeTCP) == nil {
				return false
			}
		case "UDP":
			if packet.Layer(layers.LayerTypeUDP) == nil {
				return false
			}
		case "ICMP":
			if packet.Layer(layers.LayerTypeICMPv4) == nil && packet.Layer(layers.LayerTypeICMPv6) == nil {
				return false
			}
			// Add more protocols as needed
		}
	}

	// Check Source and Destination IP
	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		srcIP := networkLayer.NetworkFlow().Src().String()
		dstIP := networkLayer.NetworkFlow().Dst().String()

		if r.SrcIP != "" && r.SrcIP != srcIP {
			return false
		}
		if r.DstIP != "" && r.DstIP != dstIP {
			return false
		}
	}

	// Check Source and Destination Port
	transportLayer := packet.TransportLayer()
	if transportLayer != nil {
		srcPort := transportLayer.TransportFlow().Src().String()
		dstPort := transportLayer.TransportFlow().Dst().String()

		if r.SrcPort != "" && r.SrcPort != srcPort {
			return false
		}
		if r.DstPort != "" && r.DstPort != dstPort {
			return false
		}
	}

	return true
}
