// Package auto provides lazy, portable views of files and nested containers.
package auto

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/tinyrange/trex/storage"
)

var ErrNotContainer = errors.New("not a container")
var ErrLimit = errors.New("auto limit exceeded")

// Options bounds decompression, entry indexing and recursive container traversal.
// Zero fields use the defaults. No host paths or processes are used by this API.
type Options struct {
	MaxExpandedBytes     int64
	MaxEntries, MaxDepth int
}

func (o Options) defaults() Options {
	if o.MaxExpandedBytes <= 0 {
		o.MaxExpandedBytes = 512 << 20
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 100000
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = 32
	}
	return o
}

type Metadata struct {
	Inspected  bool           `json:"inspected"`
	Name       string         `json:"name"`
	Kind       string         `json:"kind"`
	Size       int64          `json:"size"`
	Format     string         `json:"format,omitempty"`
	Container  bool           `json:"container"`
	Readable   bool           `json:"readable"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Node retains raw file bytes even when they also represent a container.
// Children are opened once, on demand. A failed parse is retained as an error.
type Node struct {
	name, kind               string
	reader                   storage.Reader
	options                  Options
	attributes               map[string]any
	detectOnce, childrenOnce sync.Once
	streamOnce               sync.Once
	streamView               View
	streamErr                error
	view                     View
	caseInsensitive          bool
	format                   string
	detectErr, childrenErr   error
	children                 []*Node
	loader                   func() ([]*Node, error)
}

func Open(reader storage.Reader, name string, options Options) *Node {
	return &Node{name: name, kind: "file", reader: reader, options: options.defaults()}
}

// Directory adapts a portable directory backend. load must return immediate
// children; names must be single path components. The returned slice is copied.
func Directory(name string, load func() ([]*Node, error), options Options) *Node {
	return &Node{name: name, kind: "directory", loader: load, options: options.defaults()}
}
func (n *Node) Reader() storage.Reader { return n.reader }
func (n *Node) Name() string           { return n.name }
func (n *Node) Summary() Metadata {
	size := int64(0)
	if n.reader != nil {
		if stream, ok := n.reader.(interface{ KnownSize() (int64, bool) }); ok {
			var known bool
			size, known = stream.KnownSize()
			if !known {
				size = -1
			}
		} else {
			size = n.reader.Size()
		}
	}
	return Metadata{Inspected: n.kind == "directory", Name: n.name, Kind: n.kind, Size: size, Container: n.kind == "directory", Readable: n.reader != nil, Attributes: n.attributes}
}
func (n *Node) Metadata() (Metadata, error) {
	m := n.Summary()
	m.Inspected = true
	if n.reader != nil {
		n.detectOnce.Do(func() {
			result, err := Identify(n.reader, n.options)
			if err == nil {
				n.format = result.Format
				n.view = result.View
			} else if !errors.Is(err, ErrNoMatch) {
				n.detectErr = err
			}
		})
		if described, ok := n.view.(interface {
			Description() (string, map[string]any)
		}); ok {
			_, attributes := described.Description()
			merged := make(map[string]any, len(m.Attributes)+len(attributes))
			for k, v := range m.Attributes {
				merged[k] = v
			}
			for k, v := range attributes {
				merged[k] = v
			}
			m.Attributes = merged
		}
		m.Format = n.format
		m.Container = n.view != nil
	}
	m.Container = m.Container || n.view != nil
	return m, n.detectErr
}
func (n *Node) Children() ([]*Node, error) {
	n.childrenOnce.Do(func() {
		if n.loader != nil {
			n.children, n.childrenErr = n.loader()
		} else {
			m, err := n.Metadata()
			if err != nil {
				n.childrenErr = err
				return
			}
			if !m.Container {
				n.childrenErr = ErrNotContainer
				return
			}
			n.children, n.childrenErr = n.expand(0)
		}
		if len(n.children) > n.options.MaxEntries {
			n.children = nil
			n.childrenErr = fmt.Errorf("%w: too many entries", ErrLimit)
		}
		if n.childrenErr != nil {
			return
		}
		seen := map[string]bool{}
		n.children = append([]*Node(nil), n.children...)
		for _, child := range n.children {
			if child.name == "" || child.name == "." || child.name == ".." || strings.ContainsAny(child.name, "/\\\x00") || seen[child.name] {
				n.childrenErr = fmt.Errorf("invalid or duplicate child name %q", child.name)
				return
			}
			seen[child.name] = true
		}
		sort.SliceStable(n.children, func(i, j int) bool {
			a, b := n.children[i], n.children[j]
			if (a.kind == "directory") != (b.kind == "directory") {
				return a.kind == "directory"
			}
			return a.name < b.name
		})
	})
	return append([]*Node(nil), n.children...), n.childrenErr
}

// Resolve crosses container boundaries using ordinary slash-separated paths.
// Dot segments, NULs and backslashes are rejected, never normalized away.
func (n *Node) Resolve(name string) (*Node, error) {
	if strings.ContainsAny(name, "\\\x00") {
		return nil, fs.ErrInvalid
	}
	parts := strings.Split(strings.Trim(name, "/"), "/")
	if len(parts) == 1 && parts[0] == "" {
		return n, nil
	}
	if len(parts) > n.options.MaxDepth {
		return nil, fmt.Errorf("%w: path depth", ErrLimit)
	}
	current := n
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, fs.ErrInvalid
		}
		var children []*Node
		view, err := current.pagingView()
		if err != nil {
			return nil, err
		}
		if lookup, ok := view.(EntryLookup); ok {
			entry, e := lookup.Lookup(part)
			if e != nil {
				return nil, e
			}
			children = current.pageNodes([]Entry{entry})
		} else if _, ok := view.(PagedView); ok {
			for offset := 0; ; {
				page, next, _, complete, e := current.ChildPage(offset, 100)
				if e != nil {
					return nil, e
				}
				found := false
				for _, child := range page {
					if child.name == part {
						children = []*Node{child}
						found = true
						break
					}
				}
				if found || complete {
					break
				}
				offset = next
			}
		} else {
			children, err = current.Children()
		}
		if errors.Is(err, ErrNotContainer) {
			return nil, fs.ErrNotExist
		}
		if err != nil {
			return nil, err
		}
		var next *Node
		for _, child := range children {
			if child.name == part {
				next = child
				break
			}
		}
		if next == nil {
			folded, ok := current.view.(interface{ CaseInsensitive() bool })
			if current.caseInsensitive || (ok && folded.CaseInsensitive()) {
				for _, child := range children {
					if strings.EqualFold(child.name, part) {
						if next != nil {
							return nil, fs.ErrNotExist
						}
						next = child
					}
				}
			}
		}
		if next == nil {
			return nil, fs.ErrNotExist
		}
		current = next
	}
	return current, nil
}

type item struct {
	name, kind string
	reader     storage.Reader
	view       View
	attributes map[string]any
}

func (n *Node) tree(items []item) ([]*Node, error) {
	if len(items) > n.options.MaxEntries {
		return nil, fmt.Errorf("%w: entry count", ErrLimit)
	}
	root := Directory("", nil, n.options)
	maps := map[*Node]map[string]*Node{root: {}}
	count := 0
	for _, it := range items {
		raw := strings.ReplaceAll(it.name, "\\", "/")
		for _, part := range strings.Split(raw, "/") {
			if part == ".." || strings.ContainsRune(part, 0) {
				return nil, fmt.Errorf("unsafe archive path %q", it.name)
			}
		}
		clean := strings.Trim(path.Clean("/"+raw), "/")
		if clean == "" {
			continue
		}
		parts := strings.Split(clean, "/")
		if len(parts) > n.options.MaxDepth {
			return nil, fmt.Errorf("%w: entry depth", ErrLimit)
		}
		parent := root
		for i, part := range parts {
			last := i == len(parts)-1
			children := maps[parent]
			if children == nil {
				return nil, fmt.Errorf("file/directory collision at %q", it.name)
			}
			child := children[part]
			if child == nil {
				count++
				if count > n.options.MaxEntries {
					return nil, fmt.Errorf("%w: tree entries", ErrLimit)
				}
				child = Directory(part, nil, n.options)
				children[part] = child
				parent.children = append(parent.children, child)
				maps[child] = map[string]*Node{}
			}
			if last && it.kind != "directory" {
				if len(child.children) > 0 {
					return nil, fmt.Errorf("file/directory collision at %q", it.name)
				}
				// Match existing CAB/tar lookup: the first occurrence wins.
				if child.reader == nil && child.kind == "directory" {
					child.kind = it.kind
					child.reader = it.reader
					child.view = it.view
					child.attributes = it.attributes
					delete(maps, child)
				}
			}
			parent = child
			if last && it.kind == "directory" {
				child.attributes = it.attributes
				child.view = it.view
			}
		}
	}
	for node := range maps {
		children := node.children
		if node.view != nil && len(children) != 0 {
			return nil, fmt.Errorf("explicit directory view conflicts with indexed children at %q", node.name)
		}
		node.loader = func() ([]*Node, error) { return children, nil }
	}
	return root.children, nil
}
