package tables

import (
	"fmt"
	"regexp"
	"strings"

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
	InInterface  string // Incoming interface, mainly to check for loopback
	OutInterface string // Outgoing interface
	Action       string // ACCEPT, DROP, JUMP
	JumpChain    string // Chain to jump to if action is JUMP
	LogPrefix    string // Prefix for log messages
	parentChain *Chain // pointer to chain that rule belongs to
	checkEstablished bool
}

// Creates a new rule with the given parameters
func NewRule() *Rule {
	return &Rule{}
}

func (r *Rule) SetParentChain(*Chain chain) {
	r.parentChain = chain
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
	if r.JumpChain != otherRule.JumpChain {
		return false
	}
	if r.LogPrefix != otherRule.LogPrefix {
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

	if r.checkEstablished {
		packet_info := scrIP+" "+srcPort+" "+dstIP+" "+dstPort
		parent_table := r.parentChain.parentTable
		if !parent_table.IsEstablishedConnection(packet_info) {
			return false
		}
	}

	if r.InInterface == "lo" || r.OutInterface == "lo" {
		// check if not on loopback interface
		if !(srcIP == "127.0.0.1" || dstIP == "127.0.0.1" || srcIP == "::1" || dstIP == "::1") {
			return false
		}
	}

	return true
}

// List of known iptables built-in targets
var knownTargets = map[string]bool{
	"ACCEPT": true,
	"DROP":   true,
	"REJECT": true,
	"LOG":    true,
}

func ParseRule(ruleStr string) *Rule {
	rule := &Rule{}

	parts := strings.Fields(ruleStr)
	if len(parts) < 3 {
		fmt.Println("Invalid rule format")
		return nil
	}

	rule.ChainName = parts[2]
	rule.Action = parts[len(parts)-1]

	for i := 2; i < len(parts)-1; i++ {
		switch parts[i] {
		case "-p":
			rule.Protocol = strings.ToUpper(parts[i+1])
			i++
		case "-s":
			rule.SrcIP = parts[i+1]
			i++
		case "--sport":
			rule.SrcPort = parts[i+1]
			i++
		case "-d":
			rule.DstIP = parts[i+1]
			i++
		case "--dport":
			rule.DstPort = parts[i+1]
			i++
		case "-i":
			rule.InInterface = parts[i+1]
			i++
		case "-o":
			rule.OutInterface = parts[i+1]
			i++
		case "-j":
			_, indict := knownTargets[parts[i+1]]
			if indict {
				rule.Action = parts[i+1]
			} else {
				rule.Action = "JUMP"
				rule.JumpChain = parts[i+1]
			}
			i++
			if rule.Action == "LOG" {
				logPrefixRegex := regexp.MustCompile(`--log-prefix "(.*?)"`)
				matches := logPrefixRegex.FindStringSubmatch(ruleStr)
				if len(matches) > 1 {
					rule.LogPrefix = matches[1]
				}
			}
		case "-m":
			if parts[i+1] != "conntrack" || parts[i+2] != "--ctstate":
				continue
			if parts[i+3] != "ESTABLISHED" {
				continue
			}
			rule.checkEstablished = true
		}
	}

	return rule
}
