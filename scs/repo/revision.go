package repo

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"
)

// RevisionMetadata is optional native provenance, not a review approval or test
// attestation. Parents are native snapshot IDs, never Git commit IDs.
type RevisionMetadata struct {
	Parents               []ID
	Author, Message, Task string
}
type Revision struct {
	ID                    ID
	Tree                  ID
	SourceCommit          string
	Parents               []ID
	Author, Message, Task string
}

// Revision durably stores an immutable revision without changing any name or
// the workspace's plain Snapshot identity. Parentage is explicit, not inferred
// from whichever mutable name happens to point at the tree.
func (w *Workspace) Revision(meta RevisionMetadata) (ID, error) {
	if !utf8.ValidString(meta.Author) || !utf8.ValidString(meta.Message) || !utf8.ValidString(meta.Task) {
		return "", errors.New("revision metadata must be valid UTF-8")
	}
	if len(meta.Parents) > 16 || len(meta.Author) > 1024 || len(meta.Message) > 65536 || len(meta.Task) > 4096 {
		return "", errors.New("revision metadata exceeds limits")
	}
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.readonly {
		return "", ErrReadOnly
	}
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if err := w.r.ready(); err != nil {
		return "", err
	}
	parents := append([]ID(nil), meta.Parents...)
	seen := map[ID]bool{}
	for _, id := range parents {
		if seen[id] {
			return "", errors.New("duplicate revision parent")
		}
		seen[id] = true
		if _, err := w.r.revisionLocked(id); err != nil {
			return "", err
		}
	}
	if w.s.loadErr != nil {
		return "", w.s.loadErr
	}
	tree, err := w.r.saveNode(w.s.root)
	if err != nil {
		return "", err
	}
	id, err := w.r.putJSON(snapshotKind, snapshot{Tree: tree, SourceCommit: w.s.source, Parents: parents, Author: meta.Author, Message: meta.Message, Task: meta.Task})
	if err != nil {
		return "", err
	}
	if err = w.r.sync(); err != nil {
		return "", err
	}
	return id, nil
}

func (r *Repository) revisionLocked(id ID) (Revision, error) {
	var sn snapshot
	if err := r.getJSON(id, snapshotKind, &sn); err != nil {
		return Revision{}, err
	}
	return r.validateRevision(id, sn)
}
func (r *Repository) validateRevision(id ID, sn snapshot) (Revision, error) {
	if !r.earlier(sn.Tree, id) {
		return Revision{}, errors.New("revision tree must precede snapshot")
	}
	loc, ok := r.lookupObject(key(sn.Tree))
	if !ok || loc.kind != treeKind {
		return Revision{}, errors.New("missing revision tree")
	}
	if len(sn.Parents) > 16 || len(sn.Author) > 1024 || len(sn.Message) > 65536 || len(sn.Task) > 4096 {
		return Revision{}, errors.New("invalid revision metadata")
	}
	seen := map[ID]bool{}
	for _, p := range sn.Parents {
		loc, ok := r.lookupObject(key(p))
		if !validID(p) || !ok || loc.kind != snapshotKind || !r.earlier(p, id) || seen[p] {
			return Revision{}, errors.New("invalid revision parent")
		}
		seen[p] = true
	}
	return Revision{ID: id, Tree: sn.Tree, SourceCommit: sn.SourceCommit, Parents: sn.Parents, Author: sn.Author, Message: sn.Message, Task: sn.Task}, nil
}
func (r *Repository) Revision(id ID) (Revision, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revisionLocked(id)
}

// GraphLimits bounds visited revisions, including both sides of a merge-base
// query. Zero uses 100,000. Results are exact or an error, never truncated truth.
type GraphLimits struct{ MaxVisited int }
type revisionGraph struct {
	ctx   context.Context
	r     *Repository
	max   int
	nodes map[ID]Revision
}

func newRevisionGraph(ctx context.Context, r *Repository, limits GraphLimits) (*revisionGraph, error) {
	if limits.MaxVisited < 0 {
		return nil, errors.New("invalid graph limits")
	}
	if limits.MaxVisited == 0 {
		limits.MaxVisited = 100000
	}
	return &revisionGraph{ctx: ctx, r: r, max: limits.MaxVisited, nodes: map[ID]Revision{}}, nil
}
func (g *revisionGraph) get(id ID) (Revision, error) {
	if err := g.ctx.Err(); err != nil {
		return Revision{}, err
	}
	if rev, ok := g.nodes[id]; ok {
		return rev, nil
	}
	if len(g.nodes) == g.max {
		return Revision{}, ErrQueryLimit
	}
	rev, err := g.r.indexedRevision(id)
	if err != nil {
		return Revision{}, err
	}
	g.nodes[id] = rev
	return rev, nil
}
func (g *revisionGraph) ancestors(id ID) (map[ID]bool, error) {
	seen := map[ID]bool{}
	todo := []ID{id}
	for len(todo) > 0 {
		id := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if seen[id] {
			continue
		}
		rev, err := g.get(id)
		if err != nil {
			return nil, err
		}
		seen[id] = true
		todo = append(todo, rev.Parents...)
	}
	return seen, nil
}
func (r *Repository) IsAncestor(ctx context.Context, ancestor, descendant ID, limits GraphLimits) (bool, error) {
	g, err := newRevisionGraph(ctx, r, limits)
	if err != nil {
		return false, err
	}
	if _, err := g.get(ancestor); err != nil {
		return false, err
	}
	todo := []ID{descendant}
	seen := map[ID]bool{}
	for len(todo) > 0 {
		id := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if seen[id] {
			continue
		}
		rev, err := g.get(id)
		if err != nil {
			return false, err
		}
		if id == ancestor {
			return true, nil
		}
		seen[id] = true
		todo = append(todo, rev.Parents...)
	}
	return false, nil
}

// MergeBases returns ALL best common ancestors, sorted by ID. Returning an
// arbitrary single base would be wrong for criss-cross merges.
func (r *Repository) MergeBases(ctx context.Context, a, b ID, limits GraphLimits) ([]ID, error) {
	g, err := newRevisionGraph(ctx, r, limits)
	if err != nil {
		return nil, err
	}
	left, err := g.ancestors(a)
	if err != nil {
		return nil, err
	}
	right, err := g.ancestors(b)
	if err != nil {
		return nil, err
	}
	common := map[ID]bool{}
	for id := range left {
		if right[id] {
			common[id] = true
		}
	}
	// Every ancestor of a common ancestor is common. Mark parents as non-best;
	// transitivity is represented by those parents' own entries in common.
	nonBest := map[ID]bool{}
	for id := range common {
		rev, err := g.get(id)
		if err != nil {
			return nil, err
		}
		for _, p := range rev.Parents {
			nonBest[p] = true
		}
	}
	out := []ID{}
	for id := range common {
		if !nonBest[id] {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

type HistoryPage struct {
	Revisions []Revision
	Next      ID
	Visited   int
}

// PathHistory follows FIRST parents. Next is the next unexamined revision, not
// the last result; pass it as start for continuation. Compare directory entries
// by immutable tree identity and parent mode; do not flatten directory contents.
func (r *Repository) PathHistory(ctx context.Context, start ID, p string, limits QueryLimits) (HistoryPage, error) {
	p, err := clean(p)
	if err != nil {
		return HistoryPage{}, err
	}
	if limits.Limit < 1 || limits.Limit > 10000 || limits.MaxVisited < 0 {
		return HistoryPage{}, errors.New("invalid history limits")
	}
	if limits.MaxVisited == 0 {
		limits.MaxVisited = 100000
	}
	out := HistoryPage{Revisions: []Revision{}}
	for start != "" {
		if err := ctx.Err(); err != nil {
			return HistoryPage{}, err
		}
		if out.Visited == limits.MaxVisited {
			return HistoryPage{}, ErrQueryLimit
		}
		out.Visited++
		rev, err := r.Revision(start)
		if err != nil {
			return HistoryPage{}, err
		}
		parent := ID("")
		if len(rev.Parents) > 0 {
			parent = rev.Parents[0]
		}
		a, err := r.Fork(start)
		if err != nil {
			return HistoryPage{}, err
		}
		b := r.Empty()
		if parent != "" {
			b, err = r.Fork(parent)
			if err != nil {
				return HistoryPage{}, err
			}
		}
		ai, ak, am, err := pathIdentity(a, p)
		if err != nil {
			return HistoryPage{}, err
		}
		bi, bk, bm, err := pathIdentity(b, p)
		if err != nil {
			return HistoryPage{}, err
		}
		if ai != bi || ak != bk || am != bm {
			out.Revisions = append(out.Revisions, rev)
		}
		if len(out.Revisions) == limits.Limit {
			out.Next = parent
			return out, nil
		}
		start = parent
	}
	return out, nil
}
func pathIdentity(w *Workspace, p string) (ID, string, uint32, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if err := w.prepare(p, false); err != nil {
		return "", "", 0, err
	}
	n := findNode(w.s.root, p)
	if n == nil {
		return "", "", 0, nil
	}
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	// Loaded native snapshots have durable node identities. Empty roots are the
	// sole case with no ID, and represent absence for initial history comparison.
	if n.id == "" && p != "." {
		return "", "", 0, fmt.Errorf("history path has no native identity: %q", p)
	}
	return n.id, n.entry.Kind, n.entry.Mode, nil
}
