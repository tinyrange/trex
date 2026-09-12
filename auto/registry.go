package auto

import (
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/tinyrange/trex/storage"
)

var ErrNoMatch = errors.New("unrecognized format")

// Entry is an immediate child of a View. A directory has a View; a regular
// file has a Reader. A file may also expose a View of its contained files.
// Names and metadata never contain backend paths, processes or sockets.
type Entry struct {
	Name, Kind string
	Reader     storage.Reader
	View       View
	Attributes map[string]any
}

// View is the shared read-only directory interface returned by every detector.
type View interface{ Entries() ([]Entry, error) }

// FoldedView marks directory names as case-insensitive, preserving Windows filesystem semantics.
type FoldedView struct{ View }

func (*FoldedView) CaseInsensitive() bool { return true }

type ViewFunc func() ([]Entry, error)

func (f ViewFunc) Entries() ([]Entry, error) { return f() }

// DecodedView represents a single compressed stream or virtual disk. Browsing
// transparently enters another detected container, or exposes one content file.
type DecodedView struct {
	Reader storage.Reader
	Name   string
}

func (v *DecodedView) Entries() ([]Entry, error) {
	return []Entry{{Name: v.Name, Kind: "file", Reader: v.Reader}}, nil
}

// Detector inspects a prefix of at most 64 KiB. A candidate may read further
// through source to confirm structures that cannot be identified by a prefix
// (for example ISO volume descriptors). Return ErrNoMatch only when the source
// is not this format; return a diagnostic for a confirmed but malformed format.
type Detector func(prefix []byte, source storage.Reader, options Options) (View, error)
type registration struct {
	name     string
	priority int
	detect   Detector
}

var registry struct {
	sync.RWMutex
	entries []registration
}

// Register is intended for format-package init functions. Lower priorities run
// first, with names breaking ties. Registration is safe alongside identification.
func Register(name string, priority int, detector Detector) {
	if name == "" || detector == nil {
		panic("auto: invalid registration")
	}
	registry.Lock()
	defer registry.Unlock()
	for _, entry := range registry.entries {
		if entry.name == name {
			panic("auto: duplicate format " + name)
		}
	}
	registry.entries = append(registry.entries, registration{name, priority, detector})
	sort.Slice(registry.entries, func(i, j int) bool {
		a, b := registry.entries[i], registry.entries[j]
		if a.priority != b.priority {
			return a.priority < b.priority
		}
		return a.name < b.name
	})
}
func Formats() []string {
	registry.RLock()
	defer registry.RUnlock()
	out := make([]string, len(registry.entries))
	for i, r := range registry.entries {
		out[i] = r.name
	}
	return out
}

type Result struct {
	Format string
	View   View
}

func Identify(source storage.Reader, options Options) (*Result, error) {
	if source == nil {
		return nil, fmt.Errorf("auto: invalid source")
	}
	size, known := int64(0), false
	if stream, ok := source.(interface{ KnownSize() (int64, bool) }); ok {
		size, known = stream.KnownSize()
	} else {
		size, known = source.Size(), true
	}
	if known && size < 0 {
		return nil, fmt.Errorf("auto: invalid source")
	}
	prefixSize := int64(64 << 10)
	if known {
		prefixSize = min(size, prefixSize)
	}
	prefix := make([]byte, prefixSize)
	n, err := io.ReadFull(io.NewSectionReader(source, 0, prefixSize), prefix)
	if err != nil && (known || (err != io.EOF && err != io.ErrUnexpectedEOF)) {
		return nil, err
	}
	prefix = prefix[:n]
	registry.RLock()
	entries := append([]registration(nil), registry.entries...)
	registry.RUnlock()
	for _, entry := range entries {
		view, err := entry.detect(prefix, source, options.defaults())
		if errors.Is(err, ErrNoMatch) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("auto %s: %w", entry.name, err)
		}
		if view == nil {
			return nil, fmt.Errorf("auto %s: detector returned nil view", entry.name)
		}
		name := entry.name
		if described, ok := view.(interface {
			Description() (string, map[string]any)
		}); ok {
			if specific, _ := described.Description(); specific != "" {
				name = specific
			}
		}
		return &Result{Format: name, View: view}, nil
	}
	return nil, ErrNoMatch
}

// Tree indexes flattened archive paths, inferring omitted parent directories.
// Duplicate names retain their first occurrence, matching existing CAB lookup.
func Tree(entries []Entry, options Options) (View, error) {
	n := Directory("", nil, options)
	items := make([]item, len(entries))
	for i, e := range entries {
		items[i] = item{name: e.Name, kind: e.Kind, reader: e.Reader, view: e.View, attributes: e.Attributes}
	}
	children, err := n.tree(items)
	if err != nil {
		return nil, err
	}
	return nodeView(children), nil
}
func nodeView(nodes []*Node) View {
	return ViewFunc(func() ([]Entry, error) {
		out := make([]Entry, len(nodes))
		for i, n := range nodes {
			out[i] = Entry{Name: n.name, Kind: n.kind, Reader: n.reader, View: n.view, Attributes: n.attributes}
			if n.kind == "directory" && n.view == nil {
				out[i].View = ViewFunc(func() ([]Entry, error) {
					children, err := n.Children()
					if err != nil {
						return nil, err
					}
					return nodeView(children).Entries()
				})
			}
		}
		return out, nil
	})
}
func (n *Node) expand(depth int) ([]*Node, error) {
	if folded, ok := n.view.(interface{ CaseInsensitive() bool }); ok && folded.CaseInsensitive() {
		n.caseInsensitive = true
	}
	if depth >= n.options.MaxDepth {
		return nil, fmt.Errorf("%w: compression depth", ErrLimit)
	}
	if stream, ok := n.view.(*DecodedView); ok {
		name := stream.Name
		if name == "" {
			name = strings.TrimSuffix(n.name, path.Ext(n.name))
			if name == n.name || name == "" {
				name = "content"
			}
		}
		inner := Open(stream.Reader, name, n.options)
		result, err := Identify(stream.Reader, n.options)
		if err != nil && !errors.Is(err, ErrNoMatch) {
			return nil, err
		}
		if err == nil {
			inner.format, inner.view = result.Format, result.View
			inner.detectOnce.Do(func() {})
			children, err := inner.expand(depth + 1)
			n.caseInsensitive = inner.caseInsensitive
			return children, err
		}
		// Ordinary decoded files need an exact size for metadata/range reads.
		if inner.reader.Size() < 0 {
			var probe [1]byte
			_, err := inner.reader.ReadAt(probe[:], n.options.MaxExpandedBytes)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("auto: invalid decoded size")
		}
		return []*Node{inner}, nil
	}
	entries, err := n.view.Entries()
	if err != nil {
		return nil, err
	}
	out := make([]*Node, len(entries))
	for i, e := range entries {
		node := Open(e.Reader, e.Name, n.options)
		node.kind = e.Kind
		node.attributes = e.Attributes
		if e.View != nil {
			node.view = e.View
			node.detectOnce.Do(func() {}) // Explicit context takes precedence over raw-byte detection.
			node.loader = func() ([]*Node, error) { v := &Node{view: e.View, options: n.options}; return v.expand(depth + 1) }
		}
		out[i] = node
	}
	return out, nil
}

// FromView wraps an already-open directory using the same recursive node API.
func FromView(view View, name string, options Options) *Node {
	n := Directory(name, nil, options)
	n.view = view
	n.loader = func() ([]*Node, error) { return n.expand(0) }
	return n
}

// DescribedView lets an aggregate detector report the specific confirmed
// format and source metadata without expanding the common View interface.
type DescribedView struct {
	View
	Format     string
	Attributes map[string]any
}

func (v *DescribedView) Description() (string, map[string]any) { return v.Format, v.Attributes }
func (v *DescribedView) CaseInsensitive() bool {
	folded, ok := v.View.(interface{ CaseInsensitive() bool })
	return ok && folded.CaseInsensitive()
}
