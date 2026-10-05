package repo

import (
	"errors"
	"io"
	"strings"
)

// Called under Repository.mu. Git placeholders are transient; native snapshots
// retain the original SCSREPO2/3 encoding and identity.
func (r *Repository) materializeGitNode(n *node) (*node, error) {
	obj, err := r.gitObject(n.gitObject)
	if err != nil {
		return nil, err
	}
	e := n.entry
	if e.Kind != "dir" {
		if obj.Kind != GitBlob {
			return nil, errors.New("expected Git blob")
		}
		e.Size = obj.Size
		e.Body = obj.Body
		e.Blocks = obj.Blocks
		return &node{entry: e, id: n.id}, nil
	}
	if obj.Kind != GitTree {
		return nil, errors.New("expected Git tree")
	}
	// This private reader borrows the already-held Repository.mu; do not relock it.
	reader := &Reader{r: r, entry: Entry{Kind: "file", Size: obj.Size, Body: obj.Body, Blocks: obj.Blocks}, cachedBlock: -1}
	data := make([]byte, obj.Size)
	count, err := reader.readAtRepositoryLocked(data, 0)
	if err != nil && !(err == io.EOF && count == len(data)) {
		return nil, err
	}
	if count != len(data) {
		return nil, io.ErrUnexpectedEOF
	}
	next := &node{entry: e, id: n.id}
	err = ParseGitTree(data, int(n.gitObject[32]), func(g GitTreeEntry) error {
		if g.Name == "." || g.Name == ".." || strings.ContainsAny(g.Name, "/\\") {
			return errors.New("Git name cannot be represented in workspace")
		}
		if _, err := clean(g.Name); err != nil {
			return err
		}
		child := &node{lazy: true, gitObject: g.OID}
		switch g.Mode {
		case 0040000:
			child.entry = Entry{Kind: "dir", Mode: 0755}
		case 0100644:
			child.entry = Entry{Kind: "file", Mode: 0644}
		case 0100755:
			child.entry = Entry{Kind: "file", Mode: 0755}
		case 0120000:
			child.entry = Entry{Kind: "symlink", Mode: 0777}
		case 0160000:
			child = &node{entry: Entry{Kind: "gitlink", GitOID: g.OID.String()}}
		default:
			return errors.New("unsupported Git checkout mode")
		}
		if lookup(next.children, g.Name) != nil {
			return errors.New("duplicate Git tree entry")
		}
		next.children = setChild(next.children, g.Name, child)
		return nil
	})
	return next, err
}
