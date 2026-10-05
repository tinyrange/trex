package repo

import (
	"errors"
	"path"
	"strings"
)

// Placeholder nodes are never mutated. Each live workspace replaces its own
// path with materialized copies; forks/read-only views preserve existing locking
// and structural-sharing rules without races on shared descriptor fields.
func (w *Workspace) prepare(p string, recursive bool) error {
	if w.s.loadErr != nil {
		return w.s.loadErr
	}
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if e := w.r.ready(); e != nil {
		return e
	}
	n, e := w.r.loadPath(w.s.root, p, ".", 0, recursive)
	if e != nil {
		w.s.loadErr = e
		return e
	}
	w.s.root = n
	return nil
}
func (r *Repository) loadPath(n *node, p, base string, depth int, recursive bool) (*node, error) {
	if n == nil {
		return nil, nil
	}
	if depth > 256 {
		return nil, errors.New("tree depth limit exceeded")
	}
	var e error
	n, e = r.materializeNode(n, depth)
	if e != nil {
		return nil, e
	}
	if n.entry.Kind != "dir" {
		return n, nil
	}
	if p == "." {
		if !recursive {
			return n, nil
		}
		children := n.children
		changed := false
		e = eachChild(n.children, func(name string, child *node) error {
			q := path.Join(base, name)
			if _, err := clean(q); err != nil {
				return err
			}
			next, err := r.loadPath(child, ".", q, depth+1, true)
			if err != nil {
				return err
			}
			if next != child {
				children = setChild(children, name, next)
				changed = true
			}
			return nil
		})
		if e != nil {
			return nil, e
		}
		if changed {
			return &node{entry: n.entry, children: children, id: n.id}, nil
		}
		return n, nil
	}
	name, rest, nested := strings.Cut(p, "/")
	if !nested {
		rest = "."
	}
	old := lookup(n.children, name)
	if old == nil {
		return n, nil
	}
	next, e := r.loadPath(old, rest, path.Join(base, name), depth+1, recursive)
	if e != nil {
		return nil, e
	}
	if next == old {
		return n, nil
	}
	return &node{entry: n.entry, children: setChild(n.children, name, next), id: n.id}, nil
}
func (r *Repository) materializeNode(n *node, depth int) (*node, error) {
	if n.gitObject.Valid() {
		return r.materializeGitNode(n)
	}
	if !n.lazy {
		return n, nil
	}
	if n.parent != "" && !r.earlier(n.id, n.parent) {
		return nil, errors.New("directory entry must reference an earlier object")
	}
	if n.entry.Kind == "dir" {
		var t tree
		if e := r.getJSON(n.id, treeKind, &t); e != nil {
			return nil, e
		}
		out := &node{entry: n.entry, id: n.id}
		out.entry.Times = t.Times
		if t.Index == "" {
			return out, nil
		}
		if !r.earlier(t.Index, n.id) {
			return nil, errors.New("directory index must precede tree")
		}
		index, e := r.loadIndex(t.Index, 0, [32]byte{}, func(c child) (*node, error) {
			if c.Name == "" || strings.Contains(c.Name, "/") || c.Name == "." || c.Name == ".." || c.Mode > 0777 {
				return nil, errors.New("invalid tree entry")
			}
			if _, err := clean(c.Name); err != nil {
				return nil, err
			}
			return &node{entry: Entry{Kind: c.Kind, Mode: c.Mode}, id: c.ID, parent: c.parent, lazy: true}, nil
		})
		if e != nil {
			return nil, e
		}
		out.children = index
		return out, nil
	}
	var e Entry
	if err := r.getJSON(n.id, fileKind, &e); err != nil {
		return nil, err
	}
	if e.Kind != n.entry.Kind || e.Mode != n.entry.Mode || e.Size < 0 || e.Body == "" && int64(len(e.Blocks)) != e.Size/BlockSize+boolInt(e.Size%BlockSize != 0) {
		return nil, errors.New("invalid file descriptor")
	}
	if e.Body != "" {
		loc, ok := r.lookupObject(key(e.Body))
		if !ok || loc.kind != bodyKind || int64(loc.size) != e.Size || len(e.Blocks) != 0 || !r.earlier(e.Body, n.id) || e.Kind == "gitlink" {
			return nil, errors.New("invalid file body")
		}
	}
	if e.Kind == "gitlink" {
		if _, err := ParseGitOID(e.GitOID); err != nil || e.Size != 0 || len(e.Blocks) != 0 || e.Mode != 0 {
			return nil, errors.New("invalid gitlink")
		}
	} else if e.GitOID != "" {
		return nil, errors.New("unexpected gitlink ID")
	}
	for i, b := range e.Blocks {
		loc, ok := r.lookupObject(key(b))
		expected := BlockSize
		if i == len(e.Blocks)-1 && e.Size%BlockSize != 0 {
			expected = int(e.Size % BlockSize)
		}
		if !ok || loc.kind != blockKind || loc.size != expected || !r.earlier(b, n.id) {
			return nil, errors.New("missing or invalid file block")
		}
	}
	return &node{entry: e, id: n.id}, nil
}
