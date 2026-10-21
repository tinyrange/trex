package shell

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

func (s *shell) builtin(args []string, tested bool) (bool, error) {
	previous := s.status
	s.status = 0
	name, argv := args[0], args[1:]
	switch name {
	case "trap":
		return true, s.trap(argv)
	case "umask":
		return true, s.umaskBuiltin(argv)
	case "wait":
		return true, s.wait(argv)
	case "alias", "unalias", "getopts", "hash", "jobs", "kill", "type", "ulimit":
		return true, unsupported("builtin " + name)
	case ":", "true":
		return true, nil
	case "false":
		s.status = 1
		return true, nil
	case "echo":
		newline := true
		if len(argv) > 0 && argv[0] == "-n" {
			newline = false
			argv = argv[1:]
		}
		text := strings.Join(argv, " ")
		if newline {
			text += "\n"
		}
		_, err := io.WriteString(s.output(1), text)
		return true, err
	case "printf":
		return true, s.printf(argv)
	case "exit", "return":
		n := previous
		if len(argv) > 1 {
			return true, fmt.Errorf("shell: %s: too many arguments", name)
		}
		if len(argv) == 1 {
			v, err := strconv.Atoi(argv[0])
			if err != nil {
				return true, err
			}
			n = v
		}
		s.status = n & 255
		s.flow = name
		return true, nil
	case "break", "continue":
		n := 1
		if len(argv) > 1 {
			return true, fmt.Errorf("shell: %s: too many arguments", name)
		}
		if len(argv) == 1 {
			v, err := strconv.Atoi(argv[0])
			if err != nil || v < 1 {
				return true, fmt.Errorf("shell: invalid loop count")
			}
			n = v
		}
		s.flow = name
		s.levels = n
		return true, nil
	case "set":
		return true, s.setBuiltin(argv)
	case "shift":
		n := 1
		if len(argv) > 1 {
			return true, fmt.Errorf("shell: shift: too many arguments")
		}
		if len(argv) == 1 {
			v, err := strconv.Atoi(argv[0])
			if err != nil {
				return true, err
			}
			n = v
		}
		if n < 0 || n > len(s.params) {
			s.status = 1
			return true, nil
		}
		s.params = s.params[n:]
		return true, nil
	case "export", "readonly":
		if len(argv) == 0 || len(argv) == 1 && argv[0] == "-p" {
			keys := make([]string, 0, len(s.vars))
			for k, v := range s.vars {
				if name == "export" && v.Exported || name == "readonly" && v.ReadOnly {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			for _, k := range keys {
				if _, err := fmt.Fprintf(s.output(1), "%s %s='%s'\n", name, k, strings.ReplaceAll(s.vars[k].Str, "'", "'\\''")); err != nil {
					return true, err
				}
			}
			return true, nil
		}
		for _, arg := range argv {
			key, value, assigned := strings.Cut(arg, "=")
			if !validName(key) {
				return true, fmt.Errorf("shell: invalid variable %q", key)
			}
			if assigned {
				if err := s.set(key, value); err != nil {
					return true, err
				}
			}
			v := s.vars[key]
			if name == "export" {
				v.Exported = true
			} else {
				v.ReadOnly = true
			}
			s.vars[key] = v
		}
		return true, nil
	case "unset":
		functions := false
		if len(argv) > 0 && (argv[0] == "-f" || argv[0] == "-v") {
			functions = argv[0] == "-f"
			argv = argv[1:]
		}
		for _, key := range argv {
			if functions {
				delete(s.funcs, key)
			} else {
				if err := s.Set(key, expand.Variable{}); err != nil {
					return true, err
				}
			}
		}
		return true, nil
	case "pwd":
		if len(argv) > 1 || len(argv) == 1 && (argv[0] != "-L" && argv[0] != "-P") {
			return true, unsupported("pwd options")
		}
		_, err := fmt.Fprintln(s.output(1), s.dir)
		return true, err
	case "cd":
		if len(argv) > 0 && (argv[0] == "-L" || argv[0] == "-P") {
			argv = argv[1:]
		}
		if len(argv) > 1 {
			return true, s.diagnostic(fmt.Errorf("cd: too many arguments"))
		}
		dest := s.Get("HOME").String()
		if len(argv) > 0 {
			dest = argv[0]
		}
		printDir := dest == "-"
		if printDir {
			dest = s.Get("OLDPWD").String()
		}
		if dest == "" {
			return true, s.diagnostic(fmt.Errorf("cd: empty directory"))
		}
		dest = s.resolve(dest)
		st, err := s.cfg.FS.Stat(dest)
		if err != nil {
			return true, s.diagnostic(err)
		}
		if !st.IsDir() {
			return true, s.diagnostic(fmt.Errorf("cd: not a directory: %s", dest))
		}
		old := s.dir
		s.dir = dest
		if err := s.set("OLDPWD", old); err != nil {
			return true, err
		}
		if err := s.set("PWD", dest); err != nil {
			return true, err
		}
		if printDir {
			_, err = fmt.Fprintln(s.output(1), dest)
		}
		return true, err
	case "eval":
		return true, s.evaluate(strings.Join(argv, " "), s.name+":eval", tested)
	case ".":
		if len(argv) == 0 {
			return true, fmt.Errorf("shell: . requires a filename")
		}
		filename := argv[0]
		if !strings.Contains(filename, "/") {
			found := false
			for _, dir := range strings.Split(s.Get("PATH").String(), ":") {
				p := s.resolve(path.Join(dir, filename))
				if st, err := s.cfg.FS.Stat(p); err == nil && !st.IsDir() {
					filename = p
					found = true
					break
				}
			}
			if !found {
				return true, s.diagnostic(fmt.Errorf(".: %s: not found", filename))
			}
		}
		data, err := s.readFile(filename)
		if err != nil {
			return true, s.diagnostic(err)
		}
		params := s.params
		if len(argv) > 1 {
			s.params = append([]string(nil), argv[1:]...)
			defer func() { s.params = params }()
		}
		err = s.evaluate(string(data), filename, tested)
		if s.flow == "return" {
			s.flow = ""
		}
		return true, err
	case "read":
		return true, s.readBuiltin(argv)
	case "test", "[":
		if name == "[" {
			if len(argv) == 0 || argv[len(argv)-1] != "]" {
				return true, s.diagnostic(fmt.Errorf("[: missing ]"))
			}
			argv = argv[:len(argv)-1]
		}
		ok, err := s.test(argv)
		if err != nil {
			var syntaxError *testSyntaxError
			if errors.As(err, &syntaxError) {
				s.status = 2
				_, writeErr := fmt.Fprintln(s.output(2), "test:", err)
				return true, writeErr
			}
			return true, err
		}
		if !ok {
			s.status = 1
		}
		return true, nil
	case "exec":
		if len(argv) == 0 {
			return true, nil
		}
		if err := s.dispatch(argv, tested); err != nil {
			return true, err
		}
		s.flow = "exit"
		return true, nil
	case "command":
		return true, s.commandBuiltin(argv, tested)
	case "sh", "/bin/sh":
		return true, s.shellBuiltin(argv, tested)
	}
	// Ordinary utilities live in the same virtual environment, but are not
	// delegated to host commands when their option sets are unsupported.
	handled, err := s.utility(name, argv)
	if !handled {
		s.status = previous
	}
	return handled, err
}
func validName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}
func (s *shell) evaluate(text, name string, tested bool) error {
	if s.depth >= s.cfg.MaxDepth {
		return fmt.Errorf("shell: nesting budget exceeded")
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(text), name)
	if err != nil {
		return err
	}
	old := s.source
	s.source = name
	s.depth++
	defer func() { s.source = old; s.depth-- }()
	return s.list(file.Stmts, tested)
}
func (s *shell) dispatch(args []string, tested bool) error {
	handled, err := s.builtin(args, tested)
	if handled || err != nil {
		return err
	}
	if s.cfg.Command == nil {
		return s.executeFile(args, tested)
	}
	env := map[string]string{}
	for k, v := range s.vars {
		if v.Exported && v.IsSet() {
			env[k] = v.String()
		}
	}
	status, err := s.cfg.Command(s.ctx, Invocation{Args: args, Env: env, Dir: s.dir, FS: s.cfg.FS, Umask: s.umask, Stdin: s.input(), Stdout: s.output(1), Stderr: s.output(2)})
	if errors.Is(err, ErrUnhandled) {
		return s.executeFile(args, tested)
	}
	s.status = status & 255
	return err
}
func (s *shell) shellBuiltin(argv []string, tested bool) error {
	c, err := s.child()
	if err != nil {
		return err
	}
	defer func() { closeDescriptors(c.fds) }()
	c.vars = map[string]expand.Variable{}
	for k, v := range s.vars {
		if v.Exported {
			c.vars[k] = v
		}
	}
	c.funcs = map[string]*syntax.Stmt{}
	c.params = nil
	c.errexit = false
	c.nounset = false
	c.noglob = false
	text := ""
	name := "sh"
	if len(argv) > 0 && argv[0] == "-c" {
		if len(argv) < 2 {
			return fmt.Errorf("shell: sh -c requires source")
		}
		text = argv[1]
		argv = argv[2:]
		if len(argv) > 0 {
			name = argv[0]
			c.params = append([]string(nil), argv[1:]...)
		}
	} else {
		if len(argv) == 0 {
			return unsupported("sh reading standard input")
		}
		if strings.HasPrefix(argv[0], "-") {
			return unsupported("sh option " + argv[0])
		}
		data, err := s.readFile(argv[0])
		if err != nil {
			return s.diagnostic(err)
		}
		text = string(data)
		name = argv[0]
		c.params = append([]string(nil), argv[1:]...)
	}
	c.name = name
	err = c.evaluate(text, name, false)
	if err == nil {
		err = c.exitTrap()
	}
	s.status = c.status
	return err
}
func (s *shell) setBuiltin(argv []string) error {
	if len(argv) == 0 {
		keys := make([]string, 0, len(s.vars))
		for k := range s.vars {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, err := fmt.Fprintf(s.output(1), "%s='%s'\n", k, strings.ReplaceAll(s.vars[k].Str, "'", "'\\''")); err != nil {
				return err
			}
		}
		return nil
	}
	for len(argv) > 0 {
		arg := argv[0]
		argv = argv[1:]
		if arg == "--" {
			s.params = append([]string(nil), argv...)
			return nil
		}
		if len(arg) < 2 || arg[0] != '-' && arg[0] != '+' {
			s.params = append([]string{arg}, argv...)
			return nil
		}
		enable := arg[0] == '-'
		if arg == "-o" || arg == "+o" {
			if len(argv) == 0 {
				for _, opt := range []struct {
					name    string
					enabled bool
				}{{"errexit", s.errexit}, {"nounset", s.nounset}, {"noglob", s.noglob}, {"posix", true}} {
					state := "off"
					if opt.enabled {
						state = "on"
					}
					if _, err := fmt.Fprintf(s.output(1), "%s %s\n", opt.name, state); err != nil {
						return err
					}
				}
				return nil
			}
			option := argv[0]
			argv = argv[1:]
			switch option {
			case "posix":
				if !enable {
					return unsupported("disabling POSIX mode")
				}
			case "errexit":
				s.errexit = enable
			case "nounset":
				s.nounset = enable
			case "noglob":
				s.noglob = enable
			default:
				return unsupported("shell option " + option)
			}
			continue
		}
		for _, flag := range arg[1:] {
			switch flag {
			case 'e':
				s.errexit = enable
			case 'u':
				s.nounset = enable
			case 'f':
				s.noglob = enable
			default:
				return unsupported("shell option " + string(flag))
			}
		}
	}
	return nil
}
func (s *shell) readFile(name string) ([]byte, error) {
	f, err := s.cfg.FS.Open(s.resolve(name), Read)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(s.cfg.MaxSubstitutionBytes)+1))
	if len(data) > s.cfg.MaxSubstitutionBytes {
		return nil, fmt.Errorf("shell: source budget exceeded")
	}
	return data, err
}

type testSyntaxError struct{ message string }

func (e *testSyntaxError) Error() string { return e.message }
func (s *shell) test(argv []string) (bool, error) {
	switch len(argv) {
	case 0:
		return false, nil
	case 1:
		return argv[0] != "", nil
	case 2:
		if argv[0] == "!" {
			v, err := s.test(argv[1:])
			return !v, err
		}
		switch argv[0] {
		case "=", "==", "!=", "-eq", "-ne", "-lt", "-le", "-gt", "-ge":
			return false, &testSyntaxError{"missing operand"}
		case "-t":
			fd, err := strconv.Atoi(argv[1])
			if err != nil || fd < 0 {
				return false, nil
			}
			return s.terminal(fd), nil
		case "-n":
			return argv[1] != "", nil
		case "-z":
			return argv[1] == "", nil
		case "-e", "-f", "-d", "-s", "-r", "-w", "-x", "-c", "-b", "-p", "-S":
			st, err := s.cfg.FS.Stat(s.resolve(argv[1]))
			if err != nil {
				if errorsIsNotExist(err) {
					return false, nil
				}
				return false, err
			}
			switch argv[0] {
			case "-c":
				return st.Mode()&fs.ModeCharDevice != 0, nil
			case "-b":
				return st.Mode()&fs.ModeDevice != 0 && st.Mode()&fs.ModeCharDevice == 0, nil
			case "-p":
				return st.Mode()&fs.ModeNamedPipe != 0, nil
			case "-S":
				return st.Mode()&fs.ModeSocket != 0, nil
			case "-f":
				return st.Mode().IsRegular(), nil
			case "-d":
				return st.IsDir(), nil
			case "-s":
				return st.Size() > 0, nil
			case "-r":
				return st.Mode().Perm()&0444 != 0, nil
			case "-w":
				return st.Mode().Perm()&0222 != 0, nil
			case "-x":
				return st.Mode().Perm()&0111 != 0, nil
			}
			return true, nil
		}
	case 3:
		a, b := argv[0], argv[2]
		switch argv[1] {
		case "=", "==":
			return a == b, nil
		case "!=":
			return a != b, nil
		case "-eq", "-ne", "-lt", "-le", "-gt", "-ge":
			x, err := strconv.ParseInt(a, 10, 64)
			if err != nil {
				return false, err
			}
			y, err := strconv.ParseInt(b, 10, 64)
			if err != nil {
				return false, err
			}
			switch argv[1] {
			case "-eq":
				return x == y, nil
			case "-ne":
				return x != y, nil
			case "-lt":
				return x < y, nil
			case "-le":
				return x <= y, nil
			case "-gt":
				return x > y, nil
			case "-ge":
				return x >= y, nil
			}
		}
	}
	if len(argv) > 0 && argv[0] == "!" {
		v, err := s.test(argv[1:])
		return !v, err
	}
	return false, unsupported("test expression " + strings.Join(argv, " "))
}
func errorsIsNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }
