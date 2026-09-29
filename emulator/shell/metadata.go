package shell

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"
)

// MetadataFileSystem changes virtual permissions and modification time. Touch
// advances the filesystem's own clock; it does not query or mutate host state.
type MetadataFileSystem interface {
	Chmod(string, fs.FileMode) error
	Touch(string) error
}

func (m *MemoryFS) Chmod(name string, mode fs.FileMode) error {
	if err := validPath(name); err != nil {
		return err
	}
	if mode&^0777 != 0 {
		return fmt.Errorf("shell: unsupported permission bits")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[name]
	if !ok {
		return pathError("chmod", name, fs.ErrNotExist)
	}
	n.mode = n.mode&^0777 | mode
	return nil
}
func (m *MemoryFS) Touch(name string) error {
	if err := validPath(name); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[name]
	if !ok {
		return pathError("touch", name, fs.ErrNotExist)
	}
	m.clock++
	n.modified = time.Unix(0, m.clock)
	return nil
}
func (s *shell) chmod(args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		return s.diagnostic(fmt.Errorf("chmod: mode and files required"))
	}
	text := args[0]
	args = args[1:]
	f, ok := s.cfg.FS.(interface {
		Chmod(string, fs.FileMode) error
	})
	if !ok {
		return unsupported("filesystem chmod")
	}
	for _, name := range args {
		if err := s.tick(); err != nil {
			return err
		}
		st, err := s.cfg.FS.Stat(s.resolve(name))
		if err != nil {
			if err = s.diagnostic(err); err != nil {
				return err
			}
			continue
		}
		mode := st.Mode().Perm()
		if text != "" && text[0] >= '0' && text[0] <= '9' {
			n, e := strconv.ParseUint(text, 8, 32)
			err = e
			if n > 0777 {
				err = fmt.Errorf("chmod: unsupported mode bits")
			}
			mode = fs.FileMode(n)
		} else {
			mode, err = symbolicPermissions(text, mode, 0777&^s.umask)
		}
		if err != nil {
			return s.diagnostic(err)
		}
		if err = f.Chmod(s.resolve(name), mode); err != nil {
			if err = s.diagnostic(err); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *shell) touch(args []string) error {
	noCreate := false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			break
		}
		if arg == "-c" {
			noCreate = true
		} else {
			return unsupported("touch option " + arg)
		}
	}
	if len(args) == 0 {
		return s.diagnostic(fmt.Errorf("touch: files required"))
	}
	f, ok := s.cfg.FS.(interface{ Touch(string) error })
	if !ok {
		return unsupported("filesystem touch")
	}
	for _, name := range args {
		if err := s.tick(); err != nil {
			return err
		}
		name = s.resolve(name)
		_, err := s.cfg.FS.Stat(name)
		if errorsIsNotExist(err) {
			if noCreate {
				continue
			}
			file, e := s.open(name, Write|Create, 0666)
			if e != nil {
				if e = s.diagnostic(e); e != nil {
					return e
				}
				continue
			}
			if e = file.Close(); e != nil {
				return e
			}
		} else if err != nil {
			if err = s.diagnostic(err); err != nil {
				return err
			}
			continue
		}
		if err = f.Touch(name); err != nil {
			if err = s.diagnostic(err); err != nil {
				return err
			}
		}
	}
	return nil
}
