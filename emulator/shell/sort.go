package shell

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// sort is a bounded C-locale whole-line sort. Key/numeric/locale-aware modes
// require explicit implementations, not delegation to host utilities.
func (s *shell) sortLines(args []string) error {
	unique, reverse := false, false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-" {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			break
		}
		for _, c := range arg[1:] {
			switch c {
			case 'u':
				unique = true
			case 'r':
				reverse = true
			default:
				return unsupported("sort option " + arg)
			}
		}
	}
	if len(args) == 0 {
		args = []string{"-"}
	}
	var lines []string
	total := 0
	for _, name := range args {
		if err := s.tick(); err != nil {
			return err
		}
		var input io.Reader = s.input()
		var close func() error
		if name != "-" {
			f, err := s.cfg.FS.Open(s.resolve(name), Read)
			if err != nil {
				return s.diagnostic(err)
			}
			input = f
			close = f.Close
		}
		data, err := io.ReadAll(io.LimitReader(input, int64(s.cfg.MaxSubstitutionBytes-total)+1))
		if close != nil {
			close()
		}
		if err != nil {
			return err
		}
		total += len(data)
		if total > s.cfg.MaxSubstitutionBytes {
			return fmt.Errorf("sort: input budget exceeded")
		}
		if len(data) > 0 {
			lines = append(lines, strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")...)
		}
	}
	sort.Strings(lines)
	if reverse {
		for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
			lines[i], lines[j] = lines[j], lines[i]
		}
	}
	for i, line := range lines {
		if err := s.tick(); err != nil {
			return err
		}
		if unique && i > 0 && line == lines[i-1] {
			continue
		}
		if _, err := fmt.Fprintln(s.output(1), line); err != nil {
			return err
		}
	}
	return nil
}
