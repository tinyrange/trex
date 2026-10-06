// Package unixfs defines portable Unix image entries shared by archive and
// filesystem builders. Modes use Unix on-disk bits, not io/fs.FileMode.
package unixfs

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	"path"
	"sort"
	"strings"
)

const (
	Regular   uint32 = 0100000
	Directory uint32 = 0040000
	Symlink   uint32 = 0120000
	Character uint32 = 0020000
	Block     uint32 = 0060000
	FIFO      uint32 = 0010000
	Socket    uint32 = 0140000
)

type Entry struct {
	Path                  string
	Mode, UID, GID, Mtime uint32
	Data                  storage.Reader
	Target                string // symlink target, or root-relative regular-file hardlink target
	Hardlink              bool
	Major, Minor          uint32
}

func Clean(name string) (string, error) {
	if name == "" || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\x00\\") {
		return "", fmt.Errorf("unix entry: invalid path %q", name)
	}
	for _, p := range strings.Split(name, "/") {
		if p == ".." {
			return "", fmt.Errorf("unix entry: parent traversal %q", name)
		}
	}
	return path.Clean(name), nil
}

// Normalize validates entries, supplies missing parent directories, and returns
// deterministic parent-before-child order. Duplicate paths never silently win.
func Normalize(input []Entry) ([]Entry, error) {
	byPath := map[string]Entry{}
	for _, e := range input {
		p, err := Clean(e.Path)
		if err != nil {
			return nil, err
		}
		e.Path = p
		if _, ok := byPath[p]; ok {
			return nil, fmt.Errorf("unix entry: duplicate %q", p)
		}
		typ := e.Mode & 0170000
		switch typ {
		case Regular, Directory, Symlink, Character, Block, FIFO, Socket:
		default:
			return nil, fmt.Errorf("unix entry: unsupported mode %#o", e.Mode)
		}
		if e.Mode & ^uint32(0177777) != 0 {
			return nil, fmt.Errorf("unix entry: invalid mode")
		}
		if e.Hardlink {
			if typ != Regular || e.Data != nil {
				return nil, fmt.Errorf("unix entry: invalid hardlink %q", p)
			}
			e.Target, err = Clean(e.Target)
			if err != nil {
				return nil, err
			}
		} else if typ == Regular {
			if e.Target != "" {
				return nil, fmt.Errorf("unix entry: regular file has a target")
			}
			if e.Data == nil {
				e.Data = storageZero{}
			}
			if e.Data.Size() < 0 {
				return nil, fmt.Errorf("unix entry: invalid file size")
			}
		} else if e.Data != nil {
			return nil, fmt.Errorf("unix entry: non-file has data")
		}
		if typ == Symlink && (e.Target == "" || strings.ContainsRune(e.Target, 0)) {
			return nil, fmt.Errorf("unix entry: invalid symlink")
		}
		if typ != Symlink && !e.Hardlink && e.Target != "" {
			return nil, fmt.Errorf("unix entry: unexpected target")
		}
		if typ != Character && typ != Block && (e.Major != 0 || e.Minor != 0) {
			return nil, fmt.Errorf("unix entry: unexpected device number")
		}
		if p == "." && typ != Directory {
			return nil, fmt.Errorf("unix entry: root must be a directory")
		}
		byPath[p] = e
	}
	if _, ok := byPath["."]; !ok {
		byPath["."] = Entry{Path: ".", Mode: Directory | 0755}
	}
	for p := range byPath {
		for parent := path.Dir(p); p != "."; parent = path.Dir(parent) {
			if existing, ok := byPath[parent]; ok {
				if existing.Mode&0170000 != Directory {
					return nil, fmt.Errorf("unix entry: parent %q is not a directory", parent)
				}
			} else {
				byPath[parent] = Entry{Path: parent, Mode: Directory | 0755}
			}
			if parent == "." {
				break
			}
		}
	}
	for p, e := range byPath {
		if !e.Hardlink {
			continue
		}
		seen := map[string]bool{p: true}
		target := e.Target
		for {
			t, ok := byPath[target]
			if !ok || t.Mode&0170000 != Regular {
				return nil, fmt.Errorf("unix entry: missing regular hardlink target %q", target)
			}
			if seen[target] {
				return nil, fmt.Errorf("unix entry: hardlink cycle")
			}
			seen[target] = true
			if !t.Hardlink {
				// Unix hardlinks share inode metadata, not just file contents.
				if e.Mode != t.Mode || e.UID != t.UID || e.GID != t.GID || e.Mtime != t.Mtime {
					return nil, fmt.Errorf("unix entry: conflicting hardlink metadata %q", p)
				}
				e.Target = target
				byPath[p] = e
				break
			}
			target = t.Target
		}
	}
	out := make([]Entry, 0, len(byPath))
	for _, e := range byPath {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Path, out[j].Path
		if a == "." {
			return b != "."
		}
		if b == "." {
			return false
		}
		return a < b
	})
	return out, nil
}

type storageZero struct{}

func (storageZero) Size() int64                             { return 0 }
func (storageZero) ReadAt(p []byte, off int64) (int, error) { return Zero(0).ReadAt(p, off) }
