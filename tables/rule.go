package tables

import (
	"github.com/google/gopacket"
)

type Rule struct {
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

// Check if a packet matches the parameters listed in the rule struct
func (r *Rule) CheckPacketMatch(packet gopacket.Packet) bool {
	srcIP := packet.NetworkLayer().NetworkFlow().Src().String()
	dstIP := packet.NetworkLayer().NetworkFlow().Dst().String()
	if r.DstIP != "" {
		if r.DstIP != dstIP {
			return false
		}
	}
	if r.SrcIP != "" {
		if r.SrcIP != srcIP {
			return false
		}
	}
	if r.SrcPort != "" {
		if r.SrcPort != packet.TransportLayer().TransportFlow().Src().String() {
			return false
		}
	}

	if r.DstPort != "" {
		if r.DstPort != packet.TransportLayer().TransportFlow().Dst().String() {
			return false
		}
	}
	return true
}
