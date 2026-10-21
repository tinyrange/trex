package repo

import (
	"errors"
	"strings"
)

// node is immutable after installation, except for id, which is memoized under
// Repository.mu. Nodes and block lists may be shared by any number of workspaces.
// A directory's mode lives in its parent's serialized child, not its own tree ID.
type node struct {
	gitObject GitOID // transient immutable Git tree/blob placeholder
	parent    ID     // immutable index page that introduced a lazy descriptor
	lazy      bool   // immutable descriptor placeholder; materialization path-copies workspace state
	entry     Entry
	children  *childIndex
	id        ID
}

func findNode(root *node, p string) *node {
	if p == "." {
		return root
	}
	for p != "" && root != nil {
		if root.entry.Kind != "dir" {
			return nil
		}
		name, rest, _ := strings.Cut(p, "/")
		root = lookup(root.children, name)
		p = rest
	}
	return root
}
func replaceNode(root *node, p string, value *node) *node {
	if p == "." {
		return value
	}
	name, rest, nested := strings.Cut(p, "/")
	if nested {
		value = replaceNode(lookup(root.children, name), rest, value)
	}
	return &node{entry: root.entry, children: setChild(root.children, name, value)}
}
func (s *state) get(p string) (Entry, bool) {
	n := findNode(s.root, p)
	if n == nil {
		return Entry{}, false
	}
	return n.entry, true
}
func (s *state) set(p string, n *node) {
	s.root = replaceNode(s.root, p, n)
	s.snapshot = ""
}
func walkNodes(n *node, p string, visit func(string, *node) error) error {
	return eachChild(n.children, func(name string, child *node) error {
		q := name
		if p != "." {
			q = p + "/" + name
		}
		if err := visit(q, child); err != nil {
			return err
		}
		return walkNodes(child, q, visit)
	})
}

// saveNode skips unchanged filesystem subtrees; saveIndex skips unchanged
// directory pages. Cached IDs are only accessed under Repository.mu.
func (r *Repository) saveNode(n *node) (ID, error) {
	return r.saveNodeAt(n, ".", 0)
}
func (r *Repository) saveNodeAt(n *node, p string, depth int) (ID, error) {
	if depth > 256 {
		return "", errors.New("tree depth limit exceeded")
	}
	if _, err := clean(p); err != nil {
		return "", err
	}
	if n.id != "" {
		return n.id, nil
	}
	original := n
	var err error
	n, err = r.materializeNode(n, 0)
	if err != nil {
		return "", err
	}
	var id ID
	if n.entry.Kind != "dir" {
		id, err = r.putJSON(fileKind, n.entry)
	} else {
		var index ID
		index, err = r.saveIndex(n.children, p, depth)
		if err == nil {
			id, err = r.putJSON(treeKind, tree{Index: index, Times: n.entry.Times})
		}
	}
	if err == nil {
		original.id = id
		n.id = id
	}
	return id, err
}
