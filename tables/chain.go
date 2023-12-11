package tables

import (
	"container/list"
)

type Chain struct {
	chain         *list.List // List of rules in the chain
	DefaultPolicy string     // Default policy of the chain
}

// Create a new chain
func NewChain() *Chain {
	return &Chain{chain: list.New()}
}

func (c *Chain) GetRules() *list.List {
	return c.chain
}

// Flushes the chain
func (c *Chain) Flush() {
	c.chain.Init()
}

// Appends a rule to the end of the chain
func (c *Chain) AppendRule(rule *Rule) {
	if rule.Action == "" {
		rule.Action = c.DefaultPolicy
	}
	c.chain.PushBack(rule)
}

// Inserts the rule at the given index
func (c *Chain) InsertAtIndex(rule *Rule, index int) {
	if index < 0 || index > c.chain.Len() {
		return
	}
	// Check if the policy of the rule is empty and set it to defaultPolicy if so
	if rule.Action == "" {
		rule.Action = c.DefaultPolicy
	}
	if index == 0 {
		c.chain.PushFront(rule)
		return
	}
	i := 1
	for e := c.chain.Front(); e != nil; e = e.Next() {
		if i == index {
			c.chain.InsertBefore(rule, e)
			return
		}
		i++
	}
}

// Deletes the rule at the given index
func (c *Chain) DeleteAtIndex(index int) {
	if index < 0 || index > c.chain.Len() {
		return
	}
	i := 0
	for e := c.chain.Front(); e != nil; e = e.Next() {
		if i == index {
			c.chain.Remove(e)
			return
		}
		i++
	}
}

// Deletes the rule that matches the given specifications
func (c *Chain) DeleteMatchingRule(rule *Rule) {
	for e := c.chain.Front(); e != nil; e = e.Next() {
		if r, ok := e.Value.(*Rule); ok {
			if r.CheckMatch(*rule) {
				c.chain.Remove(e)
				return
			}
		}
	}
}

// Replaces the rule at the given index with the new rule
func (c *Chain) ReplaceAtIndex(newRule *Rule, index int) {
	if index < 0 || index > c.chain.Len() {
		return
	}
	i := 0
	for e := c.chain.Front(); e != nil; e = e.Next() {
		if i == index {
			c.chain.InsertBefore(newRule, e)
			c.chain.Remove(e)
			return
		}
		i++
	}
}

// Changes the policy of each rule in the chain to the new policy
func (c *Chain) ChangePolicy(newPolicy string) {
	for e := c.chain.Front(); e != nil; e = e.Next() {
		if rule, ok := e.Value.(*Rule); ok {
			rule.Action = newPolicy
		}
	}
}
