package shell

import (
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// executeFile distinguishes a command absent from the virtual installation
// (127) from a present executable needing an unimplemented interpreter (error).
func (s *shell) executeFile(args []string, tested bool) error {
	names := []string{s.resolve(args[0])}
	if !strings.Contains(args[0], "/") {
		names = nil
		if v := s.Get("PATH"); v.IsSet() {
			for _, dir := range strings.Split(v.Str, ":") {
				names = append(names, s.resolve(path.Join(dir, args[0])))
			}
		}
	}
	denied := false
	for _, name := range names {
		st, err := s.cfg.FS.Stat(name)
		if err != nil {
			if errorsIsNotExist(err) {
				continue
			}
			return err
		}
		if st.IsDir() || st.Mode().Perm()&0111 == 0 {
			denied = true
			continue
		}
		data, err := s.readFile(name)
		if err != nil {
			return err
		}
		if strings.HasPrefix(string(data), "\x7fELF") {
			return unsupported("Linux ELF execution: " + name)
		}
		line, _, _ := strings.Cut(string(data), "\n")
		if strings.HasPrefix(line, "#!") {
			interpreter := strings.Fields(strings.TrimPrefix(line, "#!"))
			if len(interpreter) != 1 || (interpreter[0] != "/bin/sh" && interpreter[0] != "/usr/bin/sh") {
				return unsupported("script interpreter " + line)
			}
		}
		if strings.ContainsRune(line, 0) {
			return unsupported("binary format: " + name)
		}
		return s.shellBuiltin(append([]string{name}, args[1:]...), tested)
	}
	s.status = 127
	if denied {
		s.status = 126
	}
	_, err := fmt.Fprintf(s.output(2), "%s: %s\n", args[0], map[bool]string{false: "command not found", true: fs.ErrPermission.Error()}[denied])
	return err
}
