package shell

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// diff compares bytes and emits a valid normal-format edit. Common prefix and
// suffix lines are elided; the middle is one change (not a minimal edit script).
// This bounds work and memory linearly even for adversarial input.
func (s *shell) diff(args []string) error {
	quiet := false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-" {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			break
		}
		if arg == "-q" {
			quiet = true
			continue
		}
		return unsupported("diff option " + arg)
	}
	if len(args) != 2 {
		if err := s.diagnostic(fmt.Errorf("diff: expected two files")); err != nil {
			return err
		}
		s.status = 2
		return nil
	}
	data := make([][]byte, 2)
	for i, name := range args {
		var err error
		if name == "-" {
			data[i], err = io.ReadAll(io.LimitReader(s.input(), int64(s.cfg.MaxSubstitutionBytes)+1))
			if len(data[i]) > s.cfg.MaxSubstitutionBytes {
				return fmt.Errorf("shell: diff input budget exceeded")
			}
		} else {
			data[i], err = s.readFile(name)
		}
		if err != nil {
			if e := s.diagnostic(err); e != nil {
				return e
			}
			s.status = 2
			return nil
		}
	}
	if bytes.Equal(data[0], data[1]) {
		s.status = 0
		return nil
	}
	s.status = 1
	if quiet || bytes.IndexByte(data[0], 0) >= 0 || bytes.IndexByte(data[1], 0) >= 0 {
		_, err := fmt.Fprintf(s.output(1), "Files %s and %s differ\n", args[0], args[1])
		return err
	}
	split := func(b []byte) []string {
		if len(b) == 0 {
			return nil
		}
		return strings.SplitAfter(strings.TrimSuffix(string(b), "\n"), "\n")
	}
	// Retain the final newline in line identity; a missing newline is a change.
	a, b := split(data[0]), split(data[1])
	if len(a) > 0 && data[0][len(data[0])-1] == '\n' {
		a[len(a)-1] += "\n"
	}
	if len(b) > 0 && data[1][len(data[1])-1] == '\n' {
		b[len(b)-1] += "\n"
	}
	prefix := 0
	for prefix < len(a) && prefix < len(b) && a[prefix] == b[prefix] {
		prefix++
	}
	ae, be := len(a), len(b)
	for ae > prefix && be > prefix && a[ae-1] == b[be-1] {
		ae--
		be--
	}
	span := func(first, last int) string {
		if first == last {
			return strconv.Itoa(first)
		}
		return fmt.Sprintf("%d,%d", first, last)
	}
	var header string
	switch {
	case ae == prefix:
		header = fmt.Sprintf("%da%s\n", prefix, span(prefix+1, be))
	case be == prefix:
		header = fmt.Sprintf("%sd%d\n", span(prefix+1, ae), prefix)
	default:
		header = fmt.Sprintf("%sc%s\n", span(prefix+1, ae), span(prefix+1, be))
	}
	if _, err := io.WriteString(s.output(1), header); err != nil {
		return err
	}
	emit := func(marker string, lines []string) error {
		for _, line := range lines {
			if err := s.tick(); err != nil {
				return err
			}
			if _, err := io.WriteString(s.output(1), marker+line); err != nil {
				return err
			}
			if !strings.HasSuffix(line, "\n") {
				if _, err := io.WriteString(s.output(1), "\n\\ No newline at end of file\n"); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := emit("< ", a[prefix:ae]); err != nil {
		return err
	}
	if ae > prefix && be > prefix {
		if _, err := io.WriteString(s.output(1), "---\n"); err != nil {
			return err
		}
	}
	return emit("> ", b[prefix:be])
}
