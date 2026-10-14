package repo

import (
	"container/heap"
	"context"
	"errors"
	"path"
	"strings"
)

// PathPage is lexicographically ordered. Next is the last returned path when
// more results exist. Reuse the same View across pages to pin the tree.
type PathPage struct {
	Paths   []string
	Next    string
	Visited int
}

// QueryLimits bounds output and work independently. Zero MaxVisited uses
// 100,000 candidates. Exhaustion is an error, never a partial success.
type QueryLimits struct{ Limit, MaxVisited int }

var ErrQueryLimit = errors.New("source control query work limit exceeded")

// An NFA over whole path segments; ** has an epsilon edge and a self loop.
func globState(parts, names []string) (match, descend bool) {
	states := make([]bool, len(parts)+1)
	states[0] = true
	close := func() {
		for i, part := range parts {
			if states[i] && part == "**" {
				states[i+1] = true
			}
		}
	}
	close()
	for _, name := range names {
		next := make([]bool, len(states))
		for i, part := range parts {
			if !states[i] {
				continue
			}
			if part == "**" {
				next[i] = true
			} else if ok, _ := path.Match(part, name); ok {
				next[i+1] = true
			}
		}
		states = next
		close()
	}
	for i := range parts {
		descend = descend || states[i]
	}
	return states[len(parts)], descend
}

type pathCandidate struct {
	path  string
	node  *node
	depth int
}
type pathHeap []pathCandidate

func (h pathHeap) Len() int           { return len(h) }
func (h pathHeap) Less(i, j int) bool { return h[i].path < h[j].path }
func (h pathHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *pathHeap) Push(x any)        { *h = append(*h, x.(pathCandidate)) }
func (h *pathHeap) Pop() any          { old := *h; x := old[len(old)-1]; *h = old[:len(old)-1]; return x }

// GlobPage reads directory metadata only in branches that can match pattern.
// It does not validate skipped subtrees or read file payloads. after is an
// exclusive lexical cursor, not a mutable workspace identity.
func (w *Workspace) GlobPage(ctx context.Context, pattern, after string, limits QueryLimits) (PathPage, error) {
	if _, err := Match(pattern, ""); err != nil {
		return PathPage{}, err
	}
	if after != "" {
		if _, err := clean(after); err != nil {
			return PathPage{}, err
		}
	}
	if limits.Limit < 1 || limits.Limit > 10000 || limits.MaxVisited < 0 {
		return PathPage{}, errors.New("invalid path query limits")
	}
	if limits.MaxVisited == 0 {
		limits.MaxVisited = 100000
	}
	root, err := captureReview(w)
	if err != nil {
		return PathPage{}, err
	}
	parts := strings.Split(path.Clean(pattern), "/")
	out := PathPage{Visited: 1, Paths: make([]string, 0, limits.Limit)}
	pending := &pathHeap{{path: ".", node: root}}
	for pending.Len() > 0 {
		if err := ctx.Err(); err != nil {
			return PathPage{}, err
		}
		c := heap.Pop(pending).(pathCandidate)
		if c.depth > 256 {
			return PathPage{}, errors.New("path query depth exceeded")
		}
		names := []string{}
		if c.path != "." {
			names = strings.Split(c.path, "/")
		}
		match, descend := globState(parts, names)
		if !match && !descend {
			continue
		}
		if match && c.path != "." && c.path > after {
			if len(out.Paths) == limits.Limit {
				out.Next = out.Paths[len(out.Paths)-1]
				return out, nil
			}
			out.Paths = append(out.Paths, c.path)
		}
		if !descend || c.node.entry.Kind != "dir" {
			continue
		}
		prefix := c.path + "/"
		if c.path != "." && prefix < after && !strings.HasPrefix(after, prefix) {
			continue
		}
		n, err := materializeReview(w.r, c.node, c.depth)
		if err != nil {
			return PathPage{}, err
		}
		err = eachChild(n.children, func(name string, child *node) error {
			out.Visited++
			if out.Visited > limits.MaxVisited {
				return ErrQueryLimit
			}
			p := name
			if c.path != "." {
				p = c.path + "/" + name
			}
			if _, err := clean(p); err != nil {
				return err
			}
			m, d := globState(parts, strings.Split(p, "/"))
			if m || d {
				heap.Push(pending, pathCandidate{p, child, c.depth + 1})
			}
			return ctx.Err()
		})
		if err != nil {
			return PathPage{}, err
		}
	}
	return out, nil
}
