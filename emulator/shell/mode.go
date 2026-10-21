package shell

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/tinyrange/trex/channel"
)

// ModeFileSystem creates new entries with explicit permissions, atomically with
// opening/creating them. Modes must not alter an already-existing file.
type ModeFileSystem interface {
	OpenMode(string, OpenFlags, fs.FileMode) (channel.ByteChannel, error)
	MkdirMode(string, fs.FileMode) error
}

func (s *shell) open(name string, flags OpenFlags, mode fs.FileMode) (channel.ByteChannel, error) {
	if flags&Create == 0 {
		return s.cfg.FS.Open(name, flags)
	}
	mode = mode.Perm() &^ s.umask
	if f, ok := s.cfg.FS.(interface {
		OpenMode(string, OpenFlags, fs.FileMode) (channel.ByteChannel, error)
	}); ok {
		return f.OpenMode(name, flags, mode)
	}
	if mode != 0644 {
		return nil, unsupported("filesystem creation mode")
	}
	return s.cfg.FS.Open(name, flags)
}
func (s *shell) mkdir(name string, mode fs.FileMode) error {
	if f, ok := s.cfg.FS.(interface {
		MkdirMode(string, fs.FileMode) error
	}); ok {
		return f.MkdirMode(name, mode)
	}
	if mode != 0755 {
		return unsupported("filesystem directory creation mode")
	}
	return s.cfg.FS.Mkdir(name)
}
func (s *shell) umaskBuiltin(args []string) error {
	symbolic := false
	if len(args) > 0 && args[0] == "-S" {
		symbolic = true
		args = args[1:]
	}
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		if !symbolic {
			_, err := fmt.Fprintf(s.output(1), "%04o\n", s.umask)
			return err
		}
		groups := make([]string, 3)
		for i, name := range []string{"u", "g", "o"} {
			allowed := (0777 &^ s.umask) >> uint(6-3*i)
			text := name + "="
			for j, ch := range "rwx" {
				if allowed&(4>>uint(j)) != 0 {
					text += string(ch)
				}
			}
			groups[i] = text
		}
		_, err := fmt.Fprintln(s.output(1), strings.Join(groups, ","))
		return err
	}
	if len(args) != 1 {
		return s.diagnostic(fmt.Errorf("umask: expected one mask"))
	}
	text := args[0]
	if text != "" && text[0] >= '0' && text[0] <= '9' {
		value, err := strconv.ParseUint(text, 8, 32)
		if err != nil || value > 0777 {
			return s.diagnostic(fmt.Errorf("umask: invalid mask %q", text))
		}
		s.umask = fs.FileMode(value)
		return nil
	}
	allowed, err := symbolicPermissions(text, 0777&^s.umask, 0777)
	if err != nil {
		return s.diagnostic(err)
	}
	s.umask = 0777 &^ allowed
	return nil
}

func symbolicPermissions(text string, allowed, implicitWho fs.FileMode) (fs.FileMode, error) {
	for _, clause := range strings.Split(text, ",") {
		i := 0
		who := fs.FileMode(0)
		for i < len(clause) {
			var bits fs.FileMode
			switch clause[i] {
			case 'u':
				bits = 0700
			case 'g':
				bits = 0070
			case 'o':
				bits = 0007
			case 'a':
				bits = 0777
			default:
				bits = 0
			}
			if bits == 0 {
				break
			}
			who |= bits
			i++
		}
		if who == 0 {
			who = implicitWho
		}
		if i == len(clause) {
			return 0, fmt.Errorf("invalid symbolic mode %q", text)
		}
		for i < len(clause) {
			op := clause[i]
			i++
			if op != '+' && op != '-' && op != '=' {
				return 0, fmt.Errorf("invalid symbolic mode %q", text)
			}
			perms := fs.FileMode(0)
			for i < len(clause) && clause[i] != '+' && clause[i] != '-' && clause[i] != '=' {
				var bits fs.FileMode
				switch clause[i] {
				case 'r':
					bits = 4
				case 'w':
					bits = 2
				case 'x':
					bits = 1
				case 'u':
					bits = (allowed >> 6) & 7
				case 'g':
					bits = (allowed >> 3) & 7
				case 'o':
					bits = allowed & 7
				default:
					return 0, fmt.Errorf("invalid symbolic mode %q", text)
				}
				perms |= bits | (bits << 3) | (bits << 6)
				i++
			}
			perms &= who
			switch op {
			case '+':
				allowed |= perms
			case '-':
				allowed &^= perms
			case '=':
				allowed = (allowed &^ who) | perms
			}
		}
	}
	return allowed, nil
}
