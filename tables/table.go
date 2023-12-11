package tables

import (
	"fmt"

	"github.com/google/gopacket"
)

type Table struct {
	Chains map[string]*Chain // Map of chains in the table
}

func NewTable() *Table {
	return &Table{Chains: make(map[string]*Chain)}
}

func (table *Table) ProcessChain(chain Chain, packet gopacket.Packet) string {
	rules := chain.GetRules()
	for e := rules.Front(); e != nil; e = e.Next() {
		rule := e.Value.(*Rule)
		if rule.CheckPacketMatch(packet) {
			action := rule.GetAction()
			fmt.Println("action =", action)
			switch action {
			case "ACCEPT":
				fmt.Println("ACCEPT")
				return "ACCEPT"
			case "DROP":
				return "DROP"
			case "LOG":
				// non terminating action
				fmt.Println("LOG")
				continue
			case "JUMP":
				newChain := table.Chains[rule.JumpChain]
				fmt.Println("Jumping To:", rule.JumpChain)
				jmp_result := table.ProcessChain(*newChain, packet)
				fmt.Println("Finished Jump", jmp_result)
				if jmp_result == "ACCEPT" {
					return "ACCEPT"
				} else if jmp_result == "DROP" {
					return "DROP"
				}
			default:
				fmt.Println("Invalid Action", rule.GetAction())
			}
		} else {
			fmt.Println("No Match")
		}
	}
	return "Matched"
}
