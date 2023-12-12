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
}

func NewTable() *Table {
	return &Table{Chains: make(map[string]*Chain)}
}

func (table *Table) PrintChains() {
	for _, v := range table.Chains {
		fmt.Printf("%+v\n", v)
	}
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
				chain.DefaultPolicy = policy
			}
		case "-N":
			parts := strings.Fields(strings.TrimSpace(strings.Split(line, command)[1]))
			newChain := parts[0]
			table.Chains[newChain] = NewChain()
			table.Chains[newChain].chainName = newChain
		case "-F":
			for _, v := range table.Chains {
				v.Flush()
			}
		case "-A":
			chainMatches := chainRegex.FindStringSubmatch(line)
			addChain := strings.TrimSpace(chainMatches[0])
			chain := table.Chains[addChain]
			// specs := strings.Split(strings.TrimSpace(strings.Split(strings.Split(line, command)[1], addChain)[1]), "-j")[0]
			// fmt.Println("specs =", specs)
			// actionMatches := actionRegex.FindStringSubmatch(line)
			// action := strings.TrimSpace(actionMatches[0])
			// action = strings.TrimSpace(strings.Split(action, "-j")[1])
			// check if the line contains the string "--log-prefix"
			rule := ParseRule(line)
			// fmt.Printf("rule = %+v\n", rule)
			// rule := NewRule()
			// rule.ChainName = addChain
			// rule.Action = action
			// if strings.Contains(line, "--log-prefix") {
			// 	logPrefixRegex := regexp.MustCompile(`--log-prefix\s+"([^"]+)"`)
			// 	logPrefixRegexMatches := logPrefixRegex.FindStringSubmatch(line)[1]
			// 	rule.LogPrefix = logPrefixRegexMatches
			// }
			chain.AppendRule(rule)
		case "-I":
			chainMatches := chainRegex.FindStringSubmatch(line)
			addChain := strings.TrimSpace(chainMatches[0])
			chain := table.Chains[addChain]
			indexMatches := indexRegex.FindStringSubmatch(line)
			index := strings.TrimSpace(indexMatches[0])
			numIndex, _ := strconv.Atoi(index)
			// actionMatches := actionRegex.FindStringSubmatch(line)
			// action := strings.TrimSpace(actionMatches[0])
			// action = strings.TrimSpace(strings.Split(action, "-j")[1])
			// specs := strings.TrimSpace(strings.Split(strings.Split(line, command)[1], addChain+" "+index)[1])
			// specs = strings.TrimSpace(strings.Split(specs, "-j")[0])
			rule := ParseRule(line)
			// fmt.Printf("rule = %+v\n", rule)
			// rule.ParseRule(line)
			// rule.ChainName = addChain
			// rule.Action = action
			// if strings.Contains(line, "--log-prefix") {
			// 	logPrefixRegex := regexp.MustCompile(`--log-prefix\s+"([^"]+)"`)
			// 	logPrefixRegexMatches := logPrefixRegex.FindStringSubmatch(line)[1]
			// 	rule.LogPrefix = logPrefixRegexMatches
			// }
			// if specs != "" {
			// 	fmt.Println("no specs, line =", addChain, index, action)
			// }
			// fmt.Println("specs =", specs)
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
				// actionMatches := actionRegex.FindStringSubmatch(line)
				// action := strings.TrimSpace(actionMatches[0])
				// // specs := strings.TrimSpace(strings.Split(strings.Split(line, command)[1], delChain)[1])
				// // fmt.Println("specs =", line)
				// action = strings.TrimSpace(strings.Split(action, "-j")[1])
				// rule := NewRule()
				// rule.Action = action
				// if strings.Contains(line, "--log-prefix") {
				// 	logPrefixRegex := regexp.MustCompile(`--log-prefix\s+"([^"]+)"`)
				// 	logPrefixRegexMatches := logPrefixRegex.FindStringSubmatch(line)[1]
				// 	rule.LogPrefix = logPrefixRegexMatches
				// }
				rule := ParseRule(line)
				// fmt.Printf("rule = %+v\n", rule)
				chain.DeleteMatchingRule(rule)
			}
		case "-R":
			chainMatches := chainRegex.FindStringSubmatch(line)
			addChain := strings.TrimSpace(chainMatches[0])
			chain := table.Chains[addChain]
			indexMatches := indexRegex.FindStringSubmatch(line)
			index := strings.TrimSpace(indexMatches[0])
			numIndex, _ := strconv.Atoi(index)
			// actionMatches := actionRegex.FindStringSubmatch(line)
			// action := strings.TrimSpace(actionMatches[0])
			// action = strings.TrimSpace(strings.Split(action, "-j")[1])
			// specs := strings.TrimSpace(strings.Split(strings.Split(line, command)[1], addChain)[1])
			// fmt.Println("specs =", line)
			// rule := NewRule()
			// rule.Action = action
			// if strings.Contains(line, "--log-prefix") {
			// 	logPrefixRegex := regexp.MustCompile(`--log-prefix\s+"([^"]+)"`)
			// 	logPrefixRegexMatches := logPrefixRegex.FindStringSubmatch(line)[1]
			// 	rule.LogPrefix = logPrefixRegexMatches
			// }
			rule := ParseRule(line)
			// fmt.Printf("rule = %+v\n", rule)
			chain.ReplaceAtIndex(rule, numIndex-1)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}
}
