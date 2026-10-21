package shell

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

func (s *shell) ls(args []string) error {
	directory, inode, all, byTime, long := false, false, false, false, false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			break
		}
		for _, c := range arg[1:] {
			switch c {
			case 'l', 'n':
				long = true
			case 'd':
				directory = true
			case 'i':
				inode = true
			case 'a':
				all = true
			case 't':
				byTime = true
			case '1', 'L':
			default:
				return unsupported("ls option " + string(c))
			}
		}
	}
	if len(args) == 0 {
		args = []string{"."}
	}
	type entry struct {
		name string
		info fs.FileInfo
	}
	var list []entry
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
		if !st.IsDir() || directory {
			list = append(list, entry{name, st})
			continue
		}
		if len(args) > 1 {
			return unsupported("ls multiple directory headings")
		}
		if all {
			for _, name2 := range []string{".", ".."} {
				st, err := s.cfg.FS.Stat(s.resolve(path.Join(name, name2)))
				if err != nil {
					return err
				}
				list = append(list, entry{name2, st})
			}
		}
		entries, err := s.cfg.FS.ReadDir(s.resolve(name))
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !all && strings.HasPrefix(e.Name(), ".") {
				continue
			}
			st, err := e.Info()
			if err != nil {
				return err
			}
			list = append(list, entry{e.Name(), st})
		}
	}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if byTime && !a.info.ModTime().Equal(b.info.ModTime()) {
			return a.info.ModTime().After(b.info.ModTime())
		}
		return a.name < b.name
	})
	for _, e := range list {
		prefix := ""
		if inode {
			identity, ok := e.info.(interface{ Inode() uint64 })
			if !ok {
				return unsupported("filesystem inode identity")
			}
			prefix = fmt.Sprintf("%d ", identity.Inode())
		}
		if long {
			// The virtual Unix filesystem has one root identity and no hard
			// links. Do not consult host user/group databases or host time.
			if _, ok := s.cfg.FS.(*MemoryFS); !ok {
				return unsupported("ls ownership metadata")
			}
			permissions := e.info.Mode().String()
			prefix += fmt.Sprintf("%s 1 0 0 %d %s ", permissions, e.info.Size(), e.info.ModTime().UTC().Format("Jan _2 15:04"))
		}
		if _, err := fmt.Fprintln(s.output(1), prefix+e.name); err != nil {
			return err
		}
	}
	return nil
}
