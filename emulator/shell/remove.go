package shell

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

func (s *shell) remove(command string, args []string) error {
	force, recursive := false, false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		option := args[0]
		args = args[1:]
		if option == "--" {
			break
		}
		if command == "rmdir" {
			return unsupported("rmdir option " + option)
		}
		for _, c := range option[1:] {
			switch c {
			case 'f':
				force = true
			case 'r', 'R':
				recursive = true
			default:
				return unsupported("rm option " + string(c))
			}
		}
	}
	if len(args) == 0 && !force {
		return s.diagnostic(fmt.Errorf("%s: missing operand", command))
	}
	for _, name := range args {
		p := s.resolve(name)
		if p == "/" || path.Base(name) == "." || path.Base(name) == ".." {
			return s.diagnostic(fmt.Errorf("%s: refusing to remove %s", command, name))
		}
		st, err := s.cfg.FS.Stat(p)
		if err == nil {
			if command == "rmdir" && !st.IsDir() || command == "rm" && st.IsDir() && !recursive {
				err = fmt.Errorf("%s: inappropriate file type: %s", command, p)
			} else if recursive {
				err = s.removeTree(p)
			} else {
				err = s.cfg.FS.Remove(p)
			}
		}
		if err != nil {
			if force && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err = s.diagnostic(err); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *shell) removeTree(name string) error {
	if err := s.tick(); err != nil {
		return err
	}
	st, err := s.cfg.FS.Stat(name)
	if err != nil {
		return err
	}
	if st.IsDir() {
		entries, err := s.cfg.FS.ReadDir(name)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err = s.removeTree(path.Join(name, entry.Name())); err != nil {
				return err
			}
		}
	}
	return s.cfg.FS.Remove(name)
}
