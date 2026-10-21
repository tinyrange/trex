package repo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"sort"
)

// A capture pins a persistent root without serializing or publishing it. Nodes
// are immutable except memoized IDs, which must be read under repository.mu.
func captureReview(w *Workspace) (*node, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if err := w.r.ready(); err != nil {
		return nil, err
	}
	if w.s.loadErr != nil {
		return nil, w.s.loadErr
	}
	return w.s.root, nil
}
func reviewNodeID(r *Repository, n *node) ID {
	if n == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return n.id
}
func reviewIndexID(r *Repository, n *childIndex) ID {
	if n == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return n.id
}
func materializeReview(r *Repository, n *node, depth int) (*node, error) {
	if n == nil {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return nil, err
	}
	return r.materializeNode(n, depth)
}
func sameReviewContent(a, b Entry) bool {
	return a.Kind == b.Kind && a.Size == b.Size && a.Body == b.Body && a.GitOID == b.GitOID && slices.Equal(a.Blocks, b.Blocks)
}
func describeEntry(ctx context.Context, r *Repository, e Entry) (*FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info := &FileInfo{Kind: e.Kind, Mode: e.Mode, Size: e.Size, GitOID: e.GitOID}
	switch e.Kind {
	case "file", "symlink":
		reader := &Reader{r: r, entry: e, cachedBlock: -1}
		defer reader.Close()
		if e.Kind == "file" {
			h := sha256.New()
			if _, err := io.Copy(h, contextReader{ctx, reader}); err != nil {
				return nil, err
			}
			info.SHA256 = hex.EncodeToString(h.Sum(nil))
		} else {
			target, err := io.ReadAll(contextReader{ctx, reader})
			if err != nil {
				return nil, err
			}
			info.Target = string(target)
		}
	case "dir", "gitlink":
	default:
		return nil, fmt.Errorf("unsupported kind %q", e.Kind)
	}
	return info, nil
}

type reviewWalker struct {
	ctx           context.Context
	before, after *Repository
	changes       []Change
}

func diffTrees(ctx context.Context, before, after *Workspace) ([]Change, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a, err := captureReview(before)
	if err != nil {
		return nil, err
	}
	b := a
	if before.s != after.s {
		b, err = captureReview(after)
		if err != nil {
			return nil, err
		}
	}
	d := reviewWalker{ctx: ctx, before: before.r, after: after.r, changes: make([]Change, 0)}
	if err = d.walk(".", a, b, 0); err != nil {
		return nil, err
	}
	// Radix pages are visited by hash slot rather than lexicographic path order.
	sort.Slice(d.changes, func(i, j int) bool { return d.changes[i].Path < d.changes[j].Path })
	return d.changes, nil
}
func (d *reviewWalker) record(p string, a, b *node) error {
	if p == "." {
		return nil
	} // Root metadata is not part of a workspace diff.
	var err error
	c := Change{Path: p}
	if a != nil {
		c.Before, err = describeEntry(d.ctx, d.before, a.entry)
		if err != nil {
			return fmt.Errorf("before %q: %w", p, err)
		}
	}
	if b != nil {
		c.After, err = describeEntry(d.ctx, d.after, b.entry)
		if err != nil {
			return fmt.Errorf("after %q: %w", p, err)
		}
	}
	switch {
	case a == nil:
		c.Status = "added"
	case b == nil:
		c.Status = "deleted"
	case *c.Before != *c.After:
		c.Status = "modified"
	default:
		return nil
	}
	d.changes = append(d.changes, c)
	return nil
}
func (d *reviewWalker) walk(p string, a, b *node, depth int) error {
	if err := d.ctx.Err(); err != nil {
		return err
	}
	if depth > 256 {
		return fmt.Errorf("diff tree depth limit at %q", p)
	}
	if _, err := clean(p); err != nil {
		return err
	}
	if a == nil && b == nil {
		return nil
	}
	if a != nil && b != nil {
		// Directory mode belongs to its parent, not to its own Merkle identity.
		id := reviewNodeID(d.before, a)
		same := d.before == d.after && a == b || id != "" && id == reviewNodeID(d.after, b)
		if same && a.entry.Kind == b.entry.Kind {
			if a.entry.Mode == b.entry.Mode {
				return nil
			}
			if a.entry.Kind == "dir" {
				return d.record(p, a, b)
			}
		}
	}
	var err error
	a, err = materializeReview(d.before, a, depth)
	if err != nil {
		return fmt.Errorf("before %q: %w", p, err)
	}
	b, err = materializeReview(d.after, b, depth)
	if err != nil {
		return fmt.Errorf("after %q: %w", p, err)
	}
	if a == nil || b == nil || a.entry.Kind != b.entry.Kind || a.entry.Mode != b.entry.Mode ||
		a.entry.Kind != "dir" && !sameReviewContent(a.entry, b.entry) {
		if err := d.record(p, a, b); err != nil {
			return err
		}
	}
	var ac, bc *childIndex
	if a != nil && a.entry.Kind == "dir" {
		ac = a.children
	}
	if b != nil && b.entry.Kind == "dir" {
		bc = b.children
	}
	return d.walkIndex(p, ac, bc, depth)
}
func (d *reviewWalker) walkIndex(parent string, a, b *childIndex, depth int) error {
	if err := d.ctx.Err(); err != nil {
		return err
	}
	if a == nil && b == nil {
		return nil
	}
	if a != nil && b != nil {
		id := reviewIndexID(d.before, a)
		if d.before == d.after && a == b || id != "" && id == reviewIndexID(d.after, b) {
			return nil
		}
		if a.slots != nil && b.slots != nil {
			for i := range a.slots {
				if err := d.walkIndex(parent, a.slots[i], b.slots[i], depth); err != nil {
					return err
				}
			}
			return nil
		}
	}
	// Shape changes (leaf split/collapse) use a sorted merge of the affected
	// index branch only. Persistently equal siblings have already been skipped.
	aa, bb := sortedEntries(a), sortedEntries(b)
	for i, j := 0, 0; i < len(aa) || j < len(bb); {
		var name string
		var left, right *node
		switch {
		case j == len(bb) || i < len(aa) && aa[i].name < bb[j].name:
			name, left = aa[i].name, aa[i].value
			i++
		case i == len(aa) || bb[j].name < aa[i].name:
			name, right = bb[j].name, bb[j].value
			j++
		default:
			name, left, right = aa[i].name, aa[i].value, bb[j].value
			i++
			j++
		}
		p := name
		if parent != "." {
			p = parent + "/" + name
		}
		if err := d.walk(p, left, right, depth+1); err != nil {
			return err
		}
	}
	return nil
}
