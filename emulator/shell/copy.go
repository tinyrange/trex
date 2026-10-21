package shell

import (
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
)

func (s *shell) copyMove(name string, args []string) error {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-" {
		option := args[0]
		args = args[1:]
		if option == "--" {
			break
		}
		if option != "-f" {
			return unsupported(name + " option " + option)
		}
	}
	if len(args) < 2 {
		return s.diagnostic(fmt.Errorf("%s: missing operand", name))
	}
	target := s.resolve(args[len(args)-1])
	st, err := s.cfg.FS.Stat(target)
	directory := err == nil && st.IsDir()
	if len(args) > 2 && !directory {
		return s.diagnostic(fmt.Errorf("%s: target is not a directory", name))
	}
	for _, source := range args[:len(args)-1] {
		from, to := s.resolve(source), target
		if directory {
			to = path.Join(target, path.Base(from))
		}
		if from == to {
			return s.diagnostic(fmt.Errorf("%s: source and destination are identical", name))
		}
		if name == "mv" {
			renamer, ok := s.cfg.FS.(interface{ Rename(string, string) error })
			if !ok {
				return unsupported("filesystem rename")
			}
			if err := renamer.Rename(from, to); err != nil {
				return s.diagnostic(err)
			}
			continue
		}
		sourceInfo, err := s.cfg.FS.Stat(from)
		if err != nil {
			return s.diagnostic(err)
		}
		in, err := s.cfg.FS.Open(from, Read)
		if err != nil {
			return s.diagnostic(err)
		}
		out, err := s.open(to, Write|Create|Truncate, sourceInfo.Mode().Perm())
		if err != nil {
			in.Close()
			return s.diagnostic(err)
		}
		_, err = io.Copy(out, in)
		in.Close()
		closeErr := out.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

// Rename atomically moves a regular file and retains open-file identity.
// Directory moves are explicitly unsupported until subtree operations exist.
func (m *MemoryFS) Rename(from, to string) error {
	if err := validPath(from); err != nil {
		return err
	}
	if err := validPath(to); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	source, ok := m.nodes[from]
	if !ok {
		return pathError("rename", from, fs.ErrNotExist)
	}
	if source.mode.IsDir() {
		return unsupported("directory rename")
	}
	if from == to {
		return nil
	}
	if err := m.parent(to); err != nil {
		return pathError("rename", to, err)
	}
	if target, ok := m.nodes[to]; ok {
		if target.mode.IsDir() {
			return fmt.Errorf("rename: target is a directory")
		}
		target.linked = false
		if target.opens == 0 {
			m.used -= int64(len(target.data))
		}
	}
	delete(m.nodes, from)
	m.nodes[to] = source
	return nil
}
