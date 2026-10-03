package shell

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// basicRegexp translates the POSIX BRE syntax supported by Go's regexp engine.
// Unsupported backreferences are diagnosed rather than silently changing a
// configure probe's meaning. Matching uses leftmost-longest semantics.
func basicRegexp(source string) (*regexp.Regexp, error) {
	var b strings.Builder
	bracket := false
	for i := 0; i < len(source); i++ {
		c := source[i]
		if c == '\\' {
			i++
			if i == len(source) {
				return nil, fmt.Errorf("trailing regex escape")
			}
			c = source[i]
			if c >= '1' && c <= '9' {
				return nil, unsupported("BRE backreference")
			}
			if strings.ContainsRune("(){}+?|", rune(c)) && !bracket {
				b.WriteByte(c)
			} else {
				b.WriteByte('\\')
				b.WriteByte(c)
			}
			continue
		}
		if !bracket && strings.ContainsRune("()+?{}|", rune(c)) {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
		if c == '[' {
			bracket = true
		} else if c == ']' {
			bracket = false
		}
	}
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, err
	}
	re.Longest()
	return re, nil
}

type expression struct {
	args  []string
	index int
}

func (e *expression) peek() string {
	if e.index == len(e.args) {
		return ""
	}
	return e.args[e.index]
}
func precedence(op string) int {
	switch op {
	case "|":
		return 1
	case "&":
		return 2
	case "=", "!=", "<", ">", "<=", ">=":
		return 3
	case "+", "-":
		return 4
	case "*", "/", "%":
		return 5
	case ":":
		return 6
	}
	return 0
}
func (e *expression) parse(minimum int) (string, error) {
	value, err := e.atom()
	if err != nil {
		return "", err
	}
	for e.index < len(e.args) {
		op := e.peek()
		p := precedence(op)
		if p < minimum || p == 0 {
			break
		}
		e.index++
		right, err := e.parse(p + 1)
		if err != nil {
			return "", err
		}
		value, err = exprBinary(op, value, right)
		if err != nil {
			return "", err
		}
	}
	return value, nil
}
func (e *expression) atom() (string, error) {
	if e.index == len(e.args) {
		return "", fmt.Errorf("expr: missing argument")
	}
	arg := e.args[e.index]
	e.index++
	if arg == "+" {
		if e.index == len(e.args) {
			return "", fmt.Errorf("expr: missing quoted argument")
		}
		value := e.args[e.index]
		e.index++
		return value, nil
	}
	if arg == "(" {
		value, err := e.parse(1)
		if err != nil {
			return "", err
		}
		if e.peek() != ")" {
			return "", fmt.Errorf("expr: missing )")
		}
		e.index++
		return value, nil
	}
	switch arg {
	case "length":
		v, err := e.atom()
		return strconv.Itoa(len(v)), err
	case "index":
		a, err := e.atom()
		if err != nil {
			return "", err
		}
		b, err := e.atom()
		return strconv.Itoa(strings.IndexAny(a, b) + 1), err
	case "substr":
		a, err := e.atom()
		if err != nil {
			return "", err
		}
		start, err := e.atom()
		if err != nil {
			return "", err
		}
		count, err := e.atom()
		if err != nil {
			return "", err
		}
		n, e1 := strconv.Atoi(start)
		size, e2 := strconv.Atoi(count)
		if e1 != nil || e2 != nil {
			return "", fmt.Errorf("expr: non-integer substring argument")
		}
		if n < 1 || size < 1 || n > len(a) {
			return "", nil
		}
		return a[n-1 : min(len(a), n-1+size)], nil
	case "match":
		a, err := e.atom()
		if err != nil {
			return "", err
		}
		b, err := e.atom()
		if err != nil {
			return "", err
		}
		return exprBinary(":", a, b)
	}
	return arg, nil
}
func exprTrue(s string) bool { return s != "" && s != "0" }
func exprBinary(op, a, b string) (string, error) {
	boolean := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	switch op {
	case "|":
		if exprTrue(a) {
			return a, nil
		}
		if exprTrue(b) {
			return b, nil
		}
		return "0", nil
	case "&":
		if exprTrue(a) && exprTrue(b) {
			return a, nil
		}
		return "0", nil
	case ":":
		re, err := basicRegexp("^" + b)
		if err != nil {
			return "", err
		}
		indices := re.FindStringSubmatchIndex(a)
		if re.NumSubexp() > 0 {
			if len(indices) < 4 || indices[2] < 0 {
				return "", nil
			}
			return a[indices[2]:indices[3]], nil
		}
		if indices == nil {
			return "0", nil
		}
		return strconv.Itoa(indices[1]), nil
	}
	x, xe := strconv.ParseInt(a, 10, 64)
	y, ye := strconv.ParseInt(b, 10, 64)
	if op == "=" || op == "!=" || op == "<" || op == ">" || op == "<=" || op == ">=" {
		cmp := strings.Compare(a, b)
		if xe == nil && ye == nil {
			cmp = 0
			if x < y {
				cmp = -1
			} else if x > y {
				cmp = 1
			}
		}
		switch op {
		case "=":
			return boolean(cmp == 0), nil
		case "!=":
			return boolean(cmp != 0), nil
		case "<":
			return boolean(cmp < 0), nil
		case ">":
			return boolean(cmp > 0), nil
		case "<=":
			return boolean(cmp <= 0), nil
		case ">=":
			return boolean(cmp >= 0), nil
		}
	}
	if xe != nil || ye != nil {
		return "", fmt.Errorf("expr: non-integer argument")
	}
	var n int64
	switch op {
	case "+":
		n = x + y
	case "-":
		n = x - y
	case "*":
		n = x * y
	case "/":
		if y == 0 {
			return "", fmt.Errorf("expr: division by zero")
		}
		n = x / y
	case "%":
		if y == 0 {
			return "", fmt.Errorf("expr: division by zero")
		}
		n = x % y
	default:
		return "", unsupported("expr operator " + op)
	}
	return strconv.FormatInt(n, 10), nil
}
func (s *shell) expr(args []string) error {
	e := &expression{args: args}
	value, err := e.parse(1)
	if err != nil {
		return err
	}
	if e.index != len(args) {
		return fmt.Errorf("expr: unexpected %q", e.peek())
	}
	if !exprTrue(value) {
		s.status = 1
	}
	_, err = fmt.Fprintln(s.output(1), value)
	return err
}
