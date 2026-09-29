package shell

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

func (s *shell) uniq(args []string) error {
	count, duplicates, unique := false, false, false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-" {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			break
		}
		for _, c := range arg[1:] {
			switch c {
			case 'c':
				count = true
			case 'd':
				duplicates = true
			case 'u':
				unique = true
			default:
				return unsupported("uniq option " + arg)
			}
		}
	}
	if len(args) > 2 {
		return s.diagnostic(fmt.Errorf("uniq: too many operands"))
	}
	input := s.input()
	output := s.output(1)
	if len(args) > 0 && args[0] != "-" {
		f, e := s.cfg.FS.Open(s.resolve(args[0]), Read)
		if e != nil {
			return s.diagnostic(e)
		}
		defer f.Close()
		input = f
	}
	if len(args) > 1 {
		f, e := s.open(s.resolve(args[1]), Write|Create|Truncate, 0666)
		if e != nil {
			return s.diagnostic(e)
		}
		defer f.Close()
		output = f
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), s.cfg.MaxSubstitutionBytes)
	previous, n := "", 0
	emit := func() error {
		if n == 0 || duplicates && !unique && n == 1 || unique && !duplicates && n > 1 {
			return nil
		}
		var e error
		if count {
			_, e = fmt.Fprintf(output, "%7d %s\n", n, previous)
		} else {
			_, e = io.WriteString(output, previous+"\n")
		}
		return e
	}
	for scanner.Scan() {
		if e := s.tick(); e != nil {
			return e
		}
		line := scanner.Text()
		if n > 0 && line != previous {
			if e := emit(); e != nil {
				return e
			}
			n = 0
		}
		previous = line
		n++
	}
	if e := scanner.Err(); e != nil {
		return e
	}
	return emit()
}
