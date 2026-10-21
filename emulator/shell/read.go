package shell

import (
	"fmt"
	"io"
	"strings"
)

func (s *shell) readBuiltin(argv []string) error {
	raw := false
	if len(argv) > 0 && argv[0] == "-r" {
		raw = true
		argv = argv[1:]
	}
	if len(argv) == 0 {
		return unsupported("read without variable names")
	}
	for _, name := range argv {
		if !validName(name) {
			return fmt.Errorf("shell: invalid read variable %q", name)
		}
	}
	var data []byte
	var quoted []bool
	one := make([]byte, 1)
	escaped := false
	for {
		if err := s.tick(); err != nil {
			return err
		}
		n, err := s.input().Read(one)
		if n == 0 {
			if err == io.EOF {
				s.status = 1
				break
			}
			if err != nil {
				return err
			}
			continue
		}
		ch := one[0]
		if !raw && !escaped && ch == '\\' {
			escaped = true
			continue
		}
		if ch == '\n' {
			if escaped {
				escaped = false
				continue
			}
			break
		}
		if len(data) == s.cfg.MaxSubstitutionBytes {
			return fmt.Errorf("shell: read input budget exceeded")
		}
		data = append(data, ch)
		quoted = append(quoted, escaped)
		escaped = false
	}
	ifs := " \t\n"
	if v := s.Get("IFS"); v.IsSet() {
		ifs = v.Str
	}
	values := readFields(data, quoted, ifs, len(argv))
	for i, name := range argv {
		if err := s.set(name, values[i]); err != nil {
			return err
		}
	}
	return nil
}

// IFS non-whitespace terminates even empty fields; adjacent IFS whitespace is
// part of that delimiter. The final variable receives unsplit remaining fields.
func readFields(data []byte, quoted []bool, ifs string, count int) []string {
	separator := func(i int) bool { return !quoted[i] && strings.IndexByte(ifs, data[i]) >= 0 }
	white := func(i int) bool { return separator(i) && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n') }
	start, end := 0, len(data)
	for start < end && white(start) {
		start++
	}
	for end > start && white(end-1) {
		end--
	}
	type field struct{ start, end int }
	var fields []field
	for i := start; i < end; {
		begin := i
		for i < end && !separator(i) {
			i++
		}
		fields = append(fields, field{begin, i})
		if i == end {
			break
		}
		for i < end && white(i) {
			i++
		}
		if i < end && separator(i) {
			i++
		}
		for i < end && white(i) {
			i++
		}
	}
	result := make([]string, count)
	for i := 0; i < count && i < len(fields); i++ {
		stop := fields[i].end
		if i == count-1 && len(fields) > count {
			stop = end
		}
		result[i] = string(data[fields[i].start:stop])
	}
	return result
}
