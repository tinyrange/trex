package shell

import (
	"fmt"
	"io"
	"strings"
)

// tr operates on the C-locale byte alphabet; no host utility is invoked.
func (s *shell) tr(args []string) error {
	del, squeeze, complement := false, false, false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-" {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			break
		}
		for _, flag := range arg[1:] {
			switch flag {
			case 'd':
				del = true
			case 's':
				squeeze = true
			case 'c', 'C':
				complement = true
			default:
				return unsupported("tr option " + arg)
			}
		}
	}
	want := 2
	if del && !squeeze || squeeze && !del && len(args) == 1 {
		want = 1
	}
	if len(args) != want {
		return s.diagnostic(fmt.Errorf("tr: incorrect operand count"))
	}
	first, err := trSet(args[0])
	if err != nil {
		return err
	}
	if complement {
		var member [256]bool
		for _, c := range first {
			member[c] = true
		}
		first = nil
		for i := 0; i < 256; i++ {
			if !member[i] {
				first = append(first, byte(i))
			}
		}
	}
	var second []byte
	if len(args) == 2 {
		second, err = trSet(args[1])
		if err != nil {
			return err
		}
	}
	var drop, repeat [256]bool
	var translate [256]byte
	for i := range translate {
		translate[i] = byte(i)
	}
	if del {
		for _, c := range first {
			drop[c] = true
		}
	} else if len(args) == 2 {
		if len(second) == 0 {
			return s.diagnostic(fmt.Errorf("tr: empty translation target"))
		}
		for i, c := range first {
			translate[c] = second[min(i, len(second)-1)]
		}
	}
	if squeeze {
		set := first
		if len(args) == 2 {
			set = second
		}
		for _, c := range set {
			repeat[c] = true
		}
	}
	input := make([]byte, 32<<10)
	output := make([]byte, 0, len(input))
	haveLast := false
	var last byte
	for {
		if err := s.tick(); err != nil {
			return err
		}
		n, readErr := s.input().Read(input)
		output = output[:0]
		for _, c := range input[:n] {
			if drop[c] {
				continue
			}
			c = translate[c]
			if squeeze && haveLast && c == last && repeat[c] {
				continue
			}
			output = append(output, c)
			last = c
			haveLast = true
		}
		if len(output) > 0 {
			if _, err := s.output(1).Write(output); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func trSet(text string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(text); {
		if strings.HasPrefix(text[i:], "[:") {
			end := strings.Index(text[i+2:], ":]")
			if end < 0 {
				return nil, unsupported("tr unterminated character class")
			}
			name := text[i+2 : i+2+end]
			class, ok := trClass(name)
			if !ok {
				return nil, unsupported("tr character class " + name)
			}
			out = append(out, class...)
			i += end + 4
			continue
		}
		if strings.HasPrefix(text[i:], "[=") || strings.HasPrefix(text[i:], "[.") || text[i] == '[' && strings.Contains(text[i:], "*") {
			return nil, unsupported("tr operand " + text[i:])
		}
		first, next, err := trByte(text, i)
		if err != nil {
			return nil, err
		}
		i = next
		if i+1 < len(text) && text[i] == '-' {
			last, next, err := trByte(text, i+1)
			if err != nil {
				return nil, err
			}
			if first > last {
				return nil, unsupported("tr descending range")
			}
			for c := int(first); c <= int(last); c++ {
				out = append(out, byte(c))
			}
			i = next
		} else {
			out = append(out, first)
		}
	}
	return out, nil
}
func trByte(text string, i int) (byte, int, error) {
	c := text[i]
	i++
	if c != 92 {
		return c, i, nil
	}
	if i == len(text) {
		return 92, i, nil
	}
	c = text[i]
	i++
	if c >= '0' && c <= '7' {
		n := int(c - '0')
		for count := 1; count < 3 && i < len(text) && text[i] >= '0' && text[i] <= '7'; count++ {
			n = n*8 + int(text[i]-'0')
			i++
		}
		if n > 255 {
			return 0, i, unsupported("tr octal escape exceeds byte")
		}
		return byte(n), i, nil
	}
	switch c {
	case 'a':
		c = 7
	case 'b':
		c = 8
	case 'f':
		c = 12
	case 'n':
		c = 10
	case 'r':
		c = 13
	case 't':
		c = 9
	case 'v':
		c = 11
	}
	return c, i, nil
}
func trClass(name string) ([]byte, bool) {
	switch name {
	case "alnum", "alpha", "blank", "cntrl", "digit", "graph", "lower", "print", "punct", "space", "upper", "xdigit":
	default:
		return nil, false
	}
	var out []byte
	for i := 0; i < 256; i++ {
		c := byte(i)
		lower := c >= 'a' && c <= 'z'
		upper := c >= 'A' && c <= 'Z'
		digit := c >= '0' && c <= '9'
		ok := false
		switch name {
		case "alnum":
			ok = lower || upper || digit
		case "alpha":
			ok = lower || upper
		case "blank":
			ok = c == 32 || c == 9
		case "cntrl":
			ok = c < 32 || c == 127
		case "digit":
			ok = digit
		case "graph":
			ok = c >= 33 && c <= 126
		case "lower":
			ok = lower
		case "print":
			ok = c >= 32 && c <= 126
		case "punct":
			ok = c >= 33 && c <= 126 && !lower && !upper && !digit
		case "space":
			ok = c == 32 || c >= 9 && c <= 13
		case "upper":
			ok = upper
		case "xdigit":
			ok = digit || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
		}
		if ok {
			out = append(out, c)
		}
	}
	return out, true
}
