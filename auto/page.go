package auto

import (
	"fmt"
)

// EntryPage contains a bounded batch in stable view order. Total is the number
// discovered so far; it is exact only when Complete is true.
type EntryPage struct {
	Entries     []Entry
	Next, Total int
	Complete    bool
}
type PagedView interface {
	View
	Page(offset, limit int) (EntryPage, error)
}

// EntryLookup resolves an already addressable child without enumerating siblings.
type EntryLookup interface {
	Lookup(name string) (Entry, error)
}

func (n *Node) pagingView() (View, error) {
	if _, err := n.Metadata(); err != nil {
		return nil, err
	}
	n.streamOnce.Do(func() {
		v := n.view
		for depth := 0; ; depth++ {
			stream, ok := v.(*DecodedView)
			if !ok {
				n.streamView = v
				return
			}
			if depth >= n.options.MaxDepth {
				n.streamErr = fmt.Errorf("%w: compression depth", ErrLimit)
				return
			}
			r, err := Identify(stream.Reader, n.options)
			if err == ErrNoMatch {
				return
			}
			if err != nil {
				n.streamErr = err
				return
			}
			v = r.View
		}
	})
	return n.streamView, n.streamErr
}
func (n *Node) pageNodes(entries []Entry) []*Node {
	out := make([]*Node, len(entries))
	for i, e := range entries {
		child := Open(e.Reader, e.Name, n.options)
		child.kind = e.Kind
		child.attributes = e.Attributes
		if e.View != nil {
			child.view = e.View
			child.detectOnce.Do(func() {})
		}
		out[i] = child
	}
	return out
}

// ChildPage avoids forcing complete enumeration of a streaming container.
func (n *Node) ChildPage(offset, limit int) (children []*Node, next, total int, complete bool, err error) {
	if offset < 0 || limit < 1 {
		return nil, 0, 0, false, fmt.Errorf("invalid page")
	}
	v, err := n.pagingView()
	if err != nil {
		return nil, 0, 0, false, err
	}
	if paged, ok := v.(PagedView); ok {
		p, err := paged.Page(offset, limit)
		return n.pageNodes(p.Entries), p.Next, p.Total, p.Complete, err
	}
	all, err := n.Children()
	if err != nil {
		return nil, 0, 0, false, err
	}
	lo := min(offset, len(all))
	hi := lo + min(limit, len(all)-lo)
	return all[lo:hi], hi, len(all), hi == len(all), nil
}
