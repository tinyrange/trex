package shell

import (
	"fmt"
	"path"
	"strings"
)

// command -v inspects functions, implemented builtins/utilities and executable
// virtual files. Callback-only commands must install a discoverable executable
// in FS; discovery never executes a callback to test whether it handles a name.
func (s *shell) commandBuiltin(args []string, tested bool) error {
	discover := false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "-v":
			discover = true
			args = args[1:]
			continue
		case "--":
			args = args[1:]
		default:
			return unsupported("command option " + args[0])
		}
		break
	}
	if len(args) == 0 {
		return nil
	}
	if !discover {
		if s.depth >= s.cfg.MaxDepth {
			return fmt.Errorf("shell: nesting budget exceeded")
		}
		s.depth++
		defer func() { s.depth-- }()
		// Functions are dispatched by call, not dispatch: bypass them here without
		// removing them from the scope of scripts or nested eval commands.
		return s.dispatch(args, tested)
	}
	for _, name := range args {
		if err := s.tick(); err != nil {
			return err
		}
		found, err := s.commandName(name)
		if err != nil {
			return err
		}
		s.status = 0
		if found == "" {
			s.status = 1
			continue
		}
		if _, err := fmt.Fprintln(s.output(1), found); err != nil {
			return err
		}
	}
	return nil
}
func (s *shell) commandName(name string) (string, error) {
	if _, ok := s.funcs[name]; ok {
		return name, nil
	}
	switch name {
	case "trap", "umask", "wait", ":", "true", "false", "echo", "printf", "exit", "return", "break", "continue", "set", "shift", "export", "readonly", "unset", "pwd", "cd", "eval", ".", "read", "test", "[", "exec", "command", "sh", "/bin/sh",
		"cat", "mkdir", "rm", "rmdir", "basename", "dirname", "expr", "ls", "sed", "grep", "egrep", "fgrep", "cp", "mv", "sleep", "diff", "tr", "sort", "touch", "chmod", "awk", "uniq", "make":
		return name, nil
	}
	names := []string{s.resolve(name)}
	if !strings.Contains(name, "/") {
		names = nil
		if v := s.Get("PATH"); v.IsSet() {
			for _, dir := range strings.Split(v.Str, ":") {
				names = append(names, s.resolve(path.Join(dir, name)))
			}
		}
	}
	for _, candidate := range names {
		st, err := s.cfg.FS.Stat(candidate)
		if err != nil {
			if errorsIsNotExist(err) {
				continue
			}
			return "", err
		}
		if !st.IsDir() && st.Mode().Perm()&0111 != 0 {
			return candidate, nil
		}
	}
	return "", nil
}
