package shell

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

func (s *shell) grep(name string, args []string) error {
	extended, fixed := name == "egrep", name == "fgrep"
	quiet, invert, ignoreCase, count, number, list, whole, silent := false, false, false, false, false, false, false, false
	var patterns []string
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-" {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			break
		}
		if arg == "-e" {
			if len(args) == 0 {
				return s.diagnostic(fmt.Errorf("grep: missing pattern"))
			}
			patterns = append(patterns, strings.Split(args[0], "\n")...)
			args = args[1:]
			continue
		}
		for _, option := range arg[1:] {
			switch option {
			case 'E':
				extended = true
			case 'F':
				fixed = true
			case 'q':
				quiet = true
			case 'v':
				invert = true
			case 'i':
				ignoreCase = true
			case 'c':
				count = true
			case 'n':
				number = true
			case 'l':
				list = true
			case 'x':
				whole = true
			case 's':
				silent = true
			default:
				return unsupported("grep option " + arg)
			}
		}
	}
	if patterns == nil {
		if len(args) == 0 {
			return s.diagnostic(fmt.Errorf("grep: missing pattern"))
		}
		patterns = strings.Split(args[0], "\n")
		args = args[1:]
	}
	var regexps []*regexp.Regexp
	for _, pattern := range patterns {
		var re *regexp.Regexp
		var err error
		if fixed {
			pattern = regexp.QuoteMeta(pattern)
		}
		if extended || fixed {
			re, err = regexp.Compile(pattern)
		} else {
			re, err = basicRegexp(pattern)
		}
		if err != nil {
			return err
		}
		pattern = re.String()
		if whole {
			pattern = "^(?:" + pattern + ")$"
		}
		if ignoreCase {
			pattern = "(?i)" + pattern
		}
		re, err = regexp.Compile(pattern)
		if err != nil {
			return err
		}
		regexps = append(regexps, re)
	}
	if len(args) == 0 {
		args = []string{"-"}
	}
	anyMatch, failed := false, false
	for _, name := range args {
		var input io.Reader = s.input()
		var closer io.Closer
		if name != "-" {
			f, err := s.cfg.FS.Open(s.resolve(name), Read)
			if err != nil {
				failed = true
				if !silent {
					if _, err := fmt.Fprintln(s.output(2), err); err != nil {
						return err
					}
				}
				continue
			}
			input = f
			closer = f
		}
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 4096), int(s.cfg.MaxSubstitutionBytes))
		line, matches := 0, 0
		for scanner.Scan() {
			if err := s.tick(); err != nil {
				if closer != nil {
					closer.Close()
				}
				return err
			}
			line++
			text := scanner.Text()
			matched := false
			for _, re := range regexps {
				if re.MatchString(text) {
					matched = true
					break
				}
			}
			if matched == invert {
				continue
			}
			matches++
			anyMatch = true
			if quiet {
				if closer != nil {
					closer.Close()
				}
				s.status = 0
				return nil
			}
			if list {
				if _, err := fmt.Fprintln(s.output(1), name); err != nil {
					if closer != nil {
						closer.Close()
					}
					return err
				}
				break
			}
			if !count {
				prefix := ""
				if len(args) > 1 {
					prefix = name + ":"
				}
				if number {
					prefix += fmt.Sprintf("%d:", line)
				}
				if _, err := fmt.Fprintln(s.output(1), prefix+text); err != nil {
					if closer != nil {
						closer.Close()
					}
					return err
				}
			}
		}
		err := scanner.Err()
		if closer != nil {
			closer.Close()
		}
		if err != nil {
			return err
		}
		if count && !list {
			prefix := ""
			if len(args) > 1 {
				prefix = name + ":"
			}
			if _, err := fmt.Fprintf(s.output(1), "%s%d\n", prefix, matches); err != nil {
				return err
			}
		}
	}
	s.status = 1
	if anyMatch {
		s.status = 0
	}
	if failed {
		s.status = 2
	}
	return nil
}
