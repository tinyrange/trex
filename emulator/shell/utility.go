package shell

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

func (s *shell) utility(name string, args []string) (bool, error) {
	if len(args) == 1 && args[0] == "--version" {
		switch name {
		case "cat", "mkdir", "rm", "rmdir", "basename", "dirname", "expr", "ls", "sed", "grep", "egrep", "fgrep", "cp", "mv":
			_, err := fmt.Fprintf(s.output(1), "%s (trex virtual Unix utilities)\n", name)
			return true, err
		}
	}
	switch name {
	case "make":
		return true, s.makeCommand(args)
	case "wc":
		return true, s.wc(args)
	case "uniq":
		return true, s.uniq(args)
	case "awk":
		return true, s.awk(args)
	case "sort":
		return true, s.sortLines(args)
	case "touch":
		return true, s.touch(args)
	case "chmod":
		return true, s.chmod(args)
	case "tr":
		return true, s.tr(args)
	case "diff":
		return true, s.diff(args)
	case "sleep":
		return true, s.sleep(args)
	case "cp", "mv":
		return true, s.copyMove(name, args)
	case "grep", "egrep", "fgrep":
		return true, s.grep(name, args)
	case "sed":
		return true, s.sed(args)
	case "ls":
		return true, s.ls(args)
	case "expr":
		return true, s.expr(args)
	case "cat":
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		if len(args) == 0 {
			args = []string{"-"}
		}
		for _, arg := range args {
			if err := s.tick(); err != nil {
				return true, err
			}
			if arg == "-" {
				if _, err := io.Copy(s.output(1), s.input()); err != nil {
					return true, err
				}
				continue
			}
			if strings.HasPrefix(arg, "-") {
				return true, unsupported("cat option " + arg)
			}
			f, err := s.cfg.FS.Open(s.resolve(arg), Read)
			if err != nil {
				if err = s.diagnostic(err); err != nil {
					return true, err
				}
				continue
			}
			_, err = io.Copy(s.output(1), f)
			f.Close()
			if err != nil {
				return true, err
			}
		}
		return true, nil
	case "mkdir":
		parents := false
		finalMode := fs.FileMode(0777) &^ s.umask
		for len(args) > 0 && strings.HasPrefix(args[0], "-") {
			option := args[0]
			args = args[1:]
			if option == "--" {
				break
			}
			if option == "-p" {
				parents = true
				continue
			}
			if !strings.HasPrefix(option, "-m") {
				return true, unsupported("mkdir option " + option)
			}
			text := strings.TrimPrefix(option, "-m")
			if text == "" {
				if len(args) == 0 {
					return true, s.diagnostic(fmt.Errorf("mkdir: mode required"))
				}
				text = args[0]
				args = args[1:]
			}
			if text == "" {
				return true, s.diagnostic(fmt.Errorf("mkdir: empty mode"))
			}
			if text[0] >= '0' && text[0] <= '9' {
				value, e := strconv.ParseUint(text, 8, 32)
				if e != nil || value > 0777 {
					return true, s.diagnostic(fmt.Errorf("mkdir: invalid mode %q", text))
				}
				finalMode = fs.FileMode(value)
			} else {
				var e error
				finalMode, e = symbolicPermissions(text, 0777, 0777)
				if e != nil {
					return true, s.diagnostic(e)
				}
			}
		}
		if len(args) == 0 {
			return true, s.diagnostic(fmt.Errorf("mkdir: missing operand"))
		}
		for _, arg := range args {
			if strings.HasPrefix(arg, "-") {
				return true, unsupported("mkdir option " + arg)
			}
			names := []string{s.resolve(arg)}
			if parents {
				names = nil
				p := "/"
				for _, part := range strings.Split(strings.TrimPrefix(s.resolve(arg), "/"), "/") {
					p = path.Join(p, part)
					names = append(names, p)
				}
			}
			for _, p := range names {
				mode := finalMode
				if parents && p != s.resolve(arg) {
					mode = (0777 &^ s.umask) | 0300
				}
				if err := s.mkdir(p, mode); err != nil {
					if parents && errors.Is(err, fs.ErrExist) {
						st, statErr := s.cfg.FS.Stat(p)
						if statErr == nil && st.IsDir() {
							continue
						}
					}
					if err = s.diagnostic(err); err != nil {
						return true, err
					}
					break
				}
			}
		}
		return true, nil
	case "rm", "rmdir":
		return true, s.remove(name, args)
	case "basename":
		if len(args) < 1 || len(args) > 2 {
			return true, s.diagnostic(fmt.Errorf("basename: expected name and optional suffix"))
		}
		value := path.Base(args[0])
		if len(args) == 2 && args[1] != value {
			value = strings.TrimSuffix(value, args[1])
		}
		_, err := fmt.Fprintln(s.output(1), value)
		return true, err
	case "dirname":
		if len(args) != 1 {
			return true, s.diagnostic(fmt.Errorf("dirname: expected one name"))
		}
		_, err := fmt.Fprintln(s.output(1), path.Dir(args[0]))
		return true, err
	}
	return false, nil
}

// printf implements format reuse, missing arguments and POSIX string/integer
// conversions. Non-POSIX or unimplemented conversions fail explicitly.
func (s *shell) printf(args []string) error {
	if len(args) == 0 {
		return s.diagnostic(fmt.Errorf("printf: missing format"))
	}
	format, args := args[0], args[1:]
	for {
		if err := s.tick(); err != nil {
			return err
		}
		before := len(args)
		stop := false
		var out strings.Builder
		for i := 0; i < len(format); {
			if format[i] == '\\' {
				text, n, end, err := escape(format[i:], false)
				if err != nil {
					return err
				}
				out.WriteString(text)
				i += n
				if end {
					stop = true
					break
				}
				continue
			}
			if format[i] != '%' {
				out.WriteByte(format[i])
				i++
				continue
			}
			start := i
			i++
			if i < len(format) && format[i] == '%' {
				out.WriteByte('%')
				i++
				continue
			}
			for i < len(format) && strings.ContainsRune("-+ #0.123456789", rune(format[i])) {
				i++
			}
			if i == len(format) {
				return fmt.Errorf("printf: incomplete conversion")
			}
			conversion := format[i]
			spec := format[start : i+1]
			i++
			// Bound format widths/precision before handing them to fmt.
			for _, n := range strings.FieldsFunc(spec, func(r rune) bool { return r < '0' || r > '9' }) {
				v, err := strconv.Atoi(n)
				if err != nil || v > s.cfg.MaxSubstitutionBytes {
					return fmt.Errorf("printf: field budget exceeded")
				}
			}
			arg := ""
			if len(args) > 0 {
				arg = args[0]
				args = args[1:]
			}
			var value any
			switch conversion {
			case 's':
				value = arg
			case 'b':
				if spec != "%b" {
					return unsupported("printf %b width")
				}
				for len(arg) > 0 {
					if arg[0] != '\\' {
						out.WriteByte(arg[0])
						arg = arg[1:]
						continue
					}
					text, n, end, err := escape(arg, true)
					if err != nil {
						return err
					}
					out.WriteString(text)
					arg = arg[n:]
					if end {
						stop = true
						break
					}
				}
				if stop {
					i = len(format)
				}
				continue
			case 'c':
				if len(arg) > 0 {
					value = arg[:1]
				} else {
					value = ""
				}
				spec = spec[:len(spec)-1] + "s"
			case 'd', 'i', 'u', 'o', 'x', 'X':
				var n int64
				var err error
				if arg != "" {
					if arg[0] == '\'' || arg[0] == '"' {
						if len(arg) > 1 {
							n = int64([]rune(arg[1:])[0])
						}
					} else {
						n, err = strconv.ParseInt(arg, 0, 64)
					}
				}
				if err != nil {
					return s.diagnostic(fmt.Errorf("printf: %w", err))
				}
				value = n
				if conversion == 'u' || conversion == 'o' || conversion == 'x' || conversion == 'X' {
					value = uint64(n)
				}
				if conversion == 'i' || conversion == 'u' {
					spec = spec[:len(spec)-1] + "d"
				}
			default:
				return unsupported("printf conversion " + spec)
			}
			fmt.Fprintf(&out, spec, value)
			if out.Len() > s.cfg.MaxSubstitutionBytes {
				return fmt.Errorf("printf: output budget exceeded")
			}
		}
		if _, err := io.WriteString(s.output(1), out.String()); err != nil {
			return err
		}
		if stop || len(args) == 0 || before == len(args) {
			return nil
		}
	}
}
func escape(text string, argument bool) (string, int, bool, error) {
	if len(text) < 2 {
		return "\\", 1, false, nil
	}
	c := text[1]
	switch c {
	case '\\':
		return "\\", 2, false, nil
	case 'a':
		return "\a", 2, false, nil
	case 'b':
		return "\b", 2, false, nil
	case 'f':
		return "\f", 2, false, nil
	case 'n':
		return "\n", 2, false, nil
	case 'r':
		return "\r", 2, false, nil
	case 't':
		return "\t", 2, false, nil
	case 'v':
		return "\v", 2, false, nil
	case 'c':
		if argument {
			return "", 2, true, nil
		}
	}
	if c >= '0' && c <= '7' {
		start := 1
		end := start
		if argument {
			if c != '0' {
				return text[:2], 2, false, nil
			}
			start = 2
			end = 2
		}
		for end < len(text) && end < start+3 && text[end] >= '0' && text[end] <= '7' {
			end++
		}
		if end == start {
			return string([]byte{0}), end, false, nil
		}
		n, _ := strconv.ParseUint(text[start:end], 8, 8)
		return string([]byte{byte(n)}), end, false, nil
	}
	return text[:2], 2, false, nil
}
