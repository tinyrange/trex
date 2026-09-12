package msi

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type conditionValue struct {
	text    string
	number  int64
	integer bool
}

func (v conditionValue) truth() bool {
	if v.integer {
		return v.number != 0
	}
	return v.text != ""
}

type conditionParser struct {
	tokens  []string
	at      int
	values  map[string]string
	unknown map[string]bool
}

// EvaluateCondition implements MSI's property/state condition language. State
// operands must be supplied explicitly by the installer planning phase.
func EvaluateCondition(expression string, values map[string]string) (bool, error) {
	return evaluateCondition(expression, values, nil)
}

type runtimeConditionError struct{ property string }

func (e runtimeConditionError) Error() string { return "runtime property " + e.property }

func evaluateCondition(expression string, values map[string]string, unknown map[string]bool) (bool, error) {
	if len(expression) > 4096 {
		return false, fmt.Errorf("msi: condition exceeds 4096 bytes")
	}
	if strings.TrimSpace(expression) == "" {
		return true, nil
	}
	p := conditionParser{values: values, unknown: unknown}
	for i := 0; i < len(expression); {
		c := expression[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			i++
			continue
		}
		if c == '"' {
			j := i + 1
			for j < len(expression) && expression[j] != '"' {
				j++
			}
			if j == len(expression) {
				return false, fmt.Errorf("msi: unterminated condition literal")
			}
			p.tokens = append(p.tokens, expression[i:j+1])
			i = j + 1
			continue
		}
		if c == '(' || c == ')' {
			p.tokens = append(p.tokens, string(c))
			i++
			continue
		}
		if strings.ContainsRune("<>=~", rune(c)) {
			j := i + 1
			for j < len(expression) && strings.ContainsRune("<>=", rune(expression[j])) {
				j++
			}
			p.tokens = append(p.tokens, expression[i:j])
			i = j
			continue
		}
		j := i
		for j < len(expression) && !unicode.IsSpace(rune(expression[j])) && !strings.ContainsRune("()<>~=\"", rune(expression[j])) {
			j++
		}
		if j == i {
			return false, fmt.Errorf("msi: invalid condition byte")
		}
		p.tokens = append(p.tokens, expression[i:j])
		i = j
	}
	result, err := p.expression(1)
	if err != nil {
		return false, err
	}
	if p.at != len(p.tokens) {
		return false, fmt.Errorf("msi: trailing condition token %s", p.tokens[p.at])
	}
	return result, nil
}
func (p *conditionParser) expression(minimum int) (bool, error) {
	left, err := p.factor()
	if err != nil {
		return false, err
	}
	for p.at < len(p.tokens) {
		op := strings.ToUpper(p.tokens[p.at])
		priority := map[string]int{"IMP": 1, "EQV": 2, "XOR": 3, "OR": 4, "AND": 5}[op]
		if priority < minimum {
			break
		}
		p.at++
		right, err := p.expression(priority + 1)
		if err != nil {
			return false, err
		}
		switch op {
		case "IMP":
			left = !left || right
		case "EQV":
			left = left == right
		case "XOR":
			left = left != right
		case "OR":
			left = left || right
		case "AND":
			left = left && right
		}
	}
	return left, nil
}
func (p *conditionParser) factor() (bool, error) {
	if p.at >= len(p.tokens) {
		return false, fmt.Errorf("msi: missing condition operand")
	}
	token := p.tokens[p.at]
	if strings.EqualFold(token, "NOT") {
		p.at++
		v, e := p.factor()
		return !v, e
	}
	if token == "(" {
		p.at++
		v, e := p.expression(1)
		if e != nil {
			return false, e
		}
		if p.at >= len(p.tokens) || p.tokens[p.at] != ")" {
			return false, fmt.Errorf("msi: missing condition parenthesis")
		}
		p.at++
		return v, nil
	}
	left, err := p.value()
	if err != nil {
		return false, err
	}
	if p.at >= len(p.tokens) {
		return left.truth(), nil
	}
	op := p.tokens[p.at]
	if !strings.ContainsAny(op, "<>=~") {
		return left.truth(), nil
	}
	p.at++
	right, err := p.value()
	if err != nil {
		return false, err
	}
	return compareCondition(left, right, op)
}
func (p *conditionParser) value() (conditionValue, error) {
	if p.at >= len(p.tokens) {
		return conditionValue{}, fmt.Errorf("msi: missing condition value")
	}
	s := p.tokens[p.at]
	p.at++
	if strings.HasPrefix(s, `"`) {
		return conditionValue{text: s[1 : len(s)-1]}, nil
	}
	if n, err := strconv.ParseInt(s, 10, 32); err == nil {
		return conditionValue{integer: true, number: n}, nil
	}
	if s == "" || s == ")" || s == "(" {
		return conditionValue{}, fmt.Errorf("msi: invalid condition operand %s", s)
	}
	if p.unknown[s] {
		return conditionValue{}, runtimeConditionError{s}
	}
	v, found := p.values[s]
	if strings.ContainsRune("$?&!", rune(s[0])) {
		if !found {
			return conditionValue{}, fmt.Errorf("msi: state unavailable for %s", s)
		}
		n, err := strconv.ParseInt(v, 10, 32)
		return conditionValue{integer: true, number: n}, err
	}
	if s[0] == '%' {
		for name, value := range p.values {
			if strings.EqualFold(name, s) {
				v = value
				break
			}
		}
	}
	return conditionValue{text: v}, nil
}
func compareCondition(a, b conditionValue, op string) (bool, error) {
	fold := strings.HasPrefix(op, "~")
	op = strings.TrimPrefix(op, "~")
	comparison := 0
	if a.integer || b.integer {
		if !a.integer {
			n, e := strconv.ParseInt(a.text, 10, 32)
			if e != nil {
				return op == "<>", nil
			}
			a.number = n
		}
		if !b.integer {
			n, e := strconv.ParseInt(b.text, 10, 32)
			if e != nil {
				return op == "<>", nil
			}
			b.number = n
		}
		switch op {
		case "><":
			return a.number&b.number != 0, nil
		case "<<":
			return (uint32(a.number) >> 16) == uint32(b.number), nil
		case ">>":
			return (uint32(a.number) & 0xffff) == uint32(b.number), nil
		}
		if a.number < b.number {
			comparison = -1
		} else if a.number > b.number {
			comparison = 1
		}
	} else {
		if fold {
			a.text = strings.ToUpper(a.text)
			b.text = strings.ToUpper(b.text)
		}
		switch op {
		case "><":
			return strings.Contains(a.text, b.text), nil
		case "<<":
			return strings.HasPrefix(a.text, b.text), nil
		case ">>":
			return strings.HasSuffix(a.text, b.text), nil
		}
		comparison = strings.Compare(a.text, b.text)
	}
	switch op {
	case "=":
		return comparison == 0, nil
	case "<>":
		return comparison != 0, nil
	case "<":
		return comparison < 0, nil
	case ">":
		return comparison > 0, nil
	case "<=":
		return comparison <= 0, nil
	case ">=":
		return comparison >= 0, nil
	}
	return false, fmt.Errorf("msi: unknown condition operator %s", op)
}
