package tables

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/gopacket"
)

type Table struct {
	Chains map[string]*Chain // Map of chains in the table
	EstablishedConnections map[string]bool
}

func NewTable() *Table {
	return &Table{
		Chains: make(map[string]*Chain),
		EstablishedConnections: make(map[string]bool),
	}
}

func (table *Table) PrintChains() {
	for _, v := range table.Chains {
		fmt.Printf("%+v\n", v)
		v.PrintRules()
	}
}

func (table *Table) IsEstablishedConnection(packetInformation string) bool {
	return table.EstablishedConnections[packetInformation]
}

func (table *Table) GetChainByName(chain_name string) *Chain {
	chain_obj, in_table := table.Chains[chain_name]
	if in_table {
		return chain_obj
	}
	return nil
}

func (table *Table) ProcessChain(chain *Chain, packet gopacket.Packet) string {
	rules := chain.GetRules()
	decision := chain.GetDefaultPolicy()
	for e := rules.Front(); e != nil; e = e.Next() {
		rule := e.Value.(*Rule)
		if rule.CheckPacketMatch(packet) {
			action := rule.GetAction()
			switch action {
			case "ACCEPT":
				decision = "ACCEPT"
				break
			case "DROP":
				decision = "DROP"
				break
			case "LOG":
				// non terminating action
				continue
			case "JUMP":
				newChain := table.Chains[rule.JumpChain]
				jmp_result := table.ProcessChain(newChain, packet)
				if jmp_result == "ACCEPT" || jmp_result == "DROP" {
					decision = jmp_result
					break
				}
			default:
				fmt.Println("Invalid Action", rule.GetAction())
			}
		}
	}
	// if accepted, mark connection as established
	if decision == "ACCEPT" {
		networkLayer := packet.NetworkLayer()
		transportLayer := packet.TransportLayer()
		if networkLayer != nil && transportLayer != nil {
			srcIP := networkLayer.NetworkFlow().Src().String()
			dstIP := networkLayer.NetworkFlow().Dst().String()
			srcPort := transportLayer.TransportFlow().Src().String()
			dstPort := transportLayer.TransportFlow().Dst().String()
			table.EstablishedConnections[srcIP+" "+srcPort+" "+dstIP+" "+dstPort] = true
		}
	}
	return decision
}

func (table *Table) LoadRules(filename string) {
	fmt.Println("Loading rules from", filename)
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	commandRegex := regexp.MustCompile(`(-F|-P|-N|-A|-I|-D|-R)`)
	chainRegex := regexp.MustCompile(` [A-Z]{3,}`)
	indexRegex := regexp.MustCompile(` [0-9]{1,}`)
	// actionRegex := regexp.MustCompile(`-j [A-Z]{3,}`)

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.Split(line, "#")[0] // Remove comments
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		commandMatches := commandRegex.FindStringSubmatch(line)
		if len(commandMatches) < 1 {
			continue
		}
		command := commandMatches[0]

		switch command {
		case "-P":
			parts := strings.Fields(strings.TrimSpace(strings.Split(line, command)[1]))
			addChain := parts[0]
			policy := parts[1]
			chain, exists := table.Chains[addChain]
			if !exists {
				fmt.Printf("Chain %s does not exist\n", addChain)
			} else {
				chain.defaultPolicy = policy
			}
		case "-N":
			parts := strings.Fields(strings.TrimSpace(strings.Split(line, command)[1]))
			newChain := parts[0]
			table.Chains[newChain] = NewChain()
			table.Chains[newChain].chainName = newChain
			table.Chains[newChain].SetParentTable(table)
		case "-F":
			for _, v := range table.Chains {
				v.Flush()
			}
		case "-A":
			chainMatches := chainRegex.FindStringSubmatch(line)
			addChain := strings.TrimSpace(chainMatches[0])
			chain := table.Chains[addChain]
			rule := ParseRule(line)
			rule.SetParentChain(chain)
			chain.AppendRule(rule)
		case "-I":
			chainMatches := chainRegex.FindStringSubmatch(line)
			addChain := strings.TrimSpace(chainMatches[0])
			chain := table.Chains[addChain]
			indexMatches := indexRegex.FindStringSubmatch(line)
			index := strings.TrimSpace(indexMatches[0])
			numIndex, _ := strconv.Atoi(index)
			rule := ParseRule(line)
			rule.SetParentChain(chain)
			chain.InsertAtIndex(rule, numIndex-1)
		case "-D":
			chainMatches := chainRegex.FindStringSubmatch(line)
			delChain := strings.TrimSpace(chainMatches[0])
			chain := table.Chains[delChain]
			indexMatches := indexRegex.FindStringSubmatch(line)
			if len(indexMatches) > 0 && strings.Contains(line, delChain+" "+indexMatches[0]) {
				index := strings.TrimSpace(indexMatches[0])
				numIndex, _ := strconv.Atoi(index)
				chain.DeleteAtIndex(numIndex - 1)
			} else {
				rule := ParseRule(line)
				chain.DeleteMatchingRule(rule)
			}
		case "-R":
			chainMatches := chainRegex.FindStringSubmatch(line)
			addChain := strings.TrimSpace(chainMatches[0])
			chain := table.Chains[addChain]
			indexMatches := indexRegex.FindStringSubmatch(line)
			index := strings.TrimSpace(indexMatches[0])
			numIndex, _ := strconv.Atoi(index)
			rule := ParseRule(line)
			rule.SetParentChain(chain)
			chain.ReplaceAtIndex(rule, numIndex-1)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}
}
