package irix

import (
	"fmt"
	"strings"
)

var machineOperators = strings.NewReplacer(
	"&&", " && ", "||", " || ", "!=", " != ", "==", " = ", "=", " = ", "!", " ! ", "(", " ( ", ")", " ) ",
)

type machineParser struct {
	tokens []string
	facts  map[string]string
	err    error
}

// Explicit expressions use boolean precedence. Old whitespace-delimited
// alternatives are handled by the legacy predicate reader in plan.go.
func machineExpression(body string, facts map[string]string) (bool, error) {
	p := machineParser{tokens: strings.Fields(machineOperators.Replace(body)), facts: facts}
	if len(p.tokens) > 256 {
		return false, fmt.Errorf("machine selector exceeds token limit")
	}
	match := p.or()
	if p.err != nil {
		return false, p.err
	}
	if len(p.tokens) != 0 {
		return false, fmt.Errorf("invalid machine selector near %q", p.tokens[0])
	}
	return match, nil
}

func (p *machineParser) eat(token string) bool {
	if len(p.tokens) == 0 || p.tokens[0] != token {
		return false
	}
	p.tokens = p.tokens[1:]
	return true
}

func (p *machineParser) word() (string, bool) {
	if len(p.tokens) == 0 || strings.ContainsAny(p.tokens[0], "!&|=()") {
		return "", false
	}
	word := p.tokens[0]
	p.tokens = p.tokens[1:]
	return word, true
}

func (p *machineParser) or() bool {
	value := p.and()
	for p.err == nil && p.eat("||") {
		next := p.and()
		value = value || next
	}
	return value
}

func (p *machineParser) and() bool {
	value := p.atom()
	for p.err == nil && p.eat("&&") {
		next := p.atom()
		value = value && next
	}
	return value
}

func (p *machineParser) atom() bool {
	if p.eat("!") {
		return !p.atom()
	}
	if p.eat("(") {
		value := p.or()
		if !p.eat(")") && p.err == nil {
			p.err = fmt.Errorf("missing closing parenthesis in machine selector")
		}
		return value
	}
	key, ok := p.word()
	if !ok {
		p.err = fmt.Errorf("expected machine selector")
		return false
	}
	negated := p.eat("!=")
	value := key
	if negated || p.eat("=") {
		value, _ = p.word() // an empty machine fact is significant
	} else {
		key = "MACHINE"
	}
	actual, ok := p.facts[key]
	if !ok {
		p.err = fmt.Errorf("missing machine fact %s", key)
		return false
	}
	return (actual == value) != negated
}
