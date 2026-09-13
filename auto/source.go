package auto

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io/fs"
	"strings"
)

// SourceContext identifies a file within its containing source tree. Paths are
// relative to Tree, not host paths. Lookup never runs format detection, follows
// links, or enters a file that happens to contain another archive.
type SourceContext struct {
	Tree View
	Path string
}

// Lookup opens a companion anywhere within the explicitly supplied tree.
// Dot components are rejected; callers must supply a tree-relative path.
func (s *SourceContext) Lookup(name string, options Options) (Entry, error) {
	if s == nil || s.Tree == nil || name == "" || strings.ContainsAny(name, "\\\x00") {
		return Entry{}, fs.ErrInvalid
	}
	parts := strings.Split(name, "/")
	options = options.defaults()
	if len(parts) > options.MaxDepth {
		return Entry{}, ErrLimit
	}
	v := s.Tree
	budget := options.MaxEntries
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return Entry{}, fs.ErrInvalid
		}
		var found Entry
		if lookup, ok := v.(EntryLookup); ok {
			var err error
			found, err = lookup.Lookup(part)
			if err != nil {
				return Entry{}, err
			}
		} else {
			entries, err := v.Entries()
			if err != nil {
				return Entry{}, err
			}
			budget -= len(entries)
			if budget < 0 {
				return Entry{}, ErrLimit
			}
			for _, entry := range entries {
				if entry.Name == part {
					if found.Name != "" {
						return Entry{}, fmt.Errorf("ambiguous companion %q", name)
					}
					found = entry
				}
			}
			if found.Name == "" {
				return Entry{}, fs.ErrNotExist
			}
		}
		if i == len(parts)-1 {
			return found, nil
		}
		if found.Kind != "directory" || found.View == nil {
			return Entry{}, fs.ErrNotExist
		}
		v = found.View
	}
	return Entry{}, fs.ErrNotExist
}

func (s *SourceContext) File(name string, options Options) (storage.Reader, error) {
	e, err := s.Lookup(name, options)
	if err != nil {
		return nil, err
	}
	if e.Reader == nil || e.Kind == "directory" {
		return nil, fs.ErrInvalid
	}
	return e.Reader, nil
}

func (n *Node) childOptions(name string) Options {
	o := n.options
	if n.reader != nil && n.view != nil {
		o.Source = &SourceContext{Tree: n.view, Path: name}
	} else if o.Source != nil {
		p := name
		if o.Source.Path != "" {
			p = o.Source.Path + "/" + name
		}
		o.Source = &SourceContext{Tree: o.Source.Tree, Path: p}
	}
	return o
}

// SourceTree grants access only to an already-open directory, never decoding a
// file in order to discover a companion tree.
func (n *Node) SourceTree(path string) (*SourceContext, error) {
	if n.reader != nil || n.view == nil {
		return nil, fmt.Errorf("auto: companion tree must be an opened directory")
	}
	if path == "" || strings.ContainsAny(path, "\\\x00") {
		return nil, fs.ErrInvalid
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return nil, fs.ErrInvalid
		}
	}
	return &SourceContext{Tree: n.view, Path: path}, nil
}
