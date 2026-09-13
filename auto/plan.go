package auto

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
)

// Plan is a proposed, read-only derived filesystem. Discovery examines a
// directory listing; Open performs content validation and construction on demand.
type Plan struct {
	ID          string               `json:"id"`
	Title       string               `json:"title"`
	Description string               `json:"description"`
	Build       func() (View, error) `json:"-"`
	once        sync.Once
	view        View
	err         error
}

func (p *Plan) Open() (View, error) {
	p.once.Do(func() {
		p.view, p.err = p.Build()
		if p.err == nil && p.view == nil {
			p.err = fmt.Errorf("plan %s returned no filesystem", p.ID)
		}
	})
	return p.view, p.err
}

// PlanDetector must inspect only listing metadata when proposing plans. The
// supplied raw directory is available to a plan's deferred Build function.
type PlanDetector func(listing []Entry, source View, options Options) ([]*Plan, error)

var planRegistry struct {
	sync.RWMutex
	detectors map[string]PlanDetector
}

func RegisterPlan(name string, detect PlanDetector) {
	planRegistry.Lock()
	defer planRegistry.Unlock()
	if name == "" || detect == nil {
		panic("invalid plan detector")
	}
	if planRegistry.detectors == nil {
		planRegistry.detectors = map[string]PlanDetector{}
	}
	if planRegistry.detectors[name] != nil {
		panic("duplicate plan detector")
	}
	planRegistry.detectors[name] = detect
}

// WithPlans returns an independent auto node enabling directory-based proposals.
// Plain auto nodes retain their original traversal and namespace.
func (n *Node) WithPlans() (*Node, error) {
	if _, err := n.Metadata(); err != nil {
		return nil, err
	}
	o := n.options
	o.plans = true
	v := Open(n.reader, n.name, o)
	v.kind = n.kind
	v.attributes = n.attributes
	v.view = n.view
	v.format = n.format
	v.caseInsensitive = n.caseInsensitive
	v.detectOnce.Do(func() {})
	if n.loader != nil {
		if v.view != nil {
			v.loader = func() ([]*Node, error) { return v.expand(0) }
		} else {
			v.loader = func() ([]*Node, error) {
				children, err := n.Children()
				if err != nil {
					return nil, err
				}
				out := make([]*Node, len(children))
				for i, c := range children {
					out[i], err = c.WithPlans()
					if err != nil {
						return nil, err
					}
				}
				return out, nil
			}
		}
	}
	return v, nil
}

func (n *Node) Plans() ([]*Plan, error) {
	if !n.options.plans {
		return nil, nil
	}
	n.planOnce.Do(func() {
		v, err := n.pagingView()
		if err != nil {
			n.planErr = err
			return
		}
		if v == nil {
			return
		}
		// Proposals never force a streaming archive to its end just to find a plan.
		var listing []Entry
		if p, ok := v.(PagedView); ok {
			page, e := p.Page(0, min(n.options.MaxEntries, 1000))
			if e != nil {
				n.planErr = e
				return
			}
			if !page.Complete {
				return
			}
			listing = page.Entries
		} else {
			listing, err = v.Entries()
			if err != nil {
				n.planErr = err
				return
			}
		}
		if len(listing) > n.options.MaxEntries {
			n.planErr = ErrLimit
			return
		}
		for _, e := range listing {
			if e.Name == "$plans" {
				return
			}
		} // Never hide a real entry.
		planRegistry.RLock()
		names := make([]string, 0, len(planRegistry.detectors))
		for name := range planRegistry.detectors {
			names = append(names, name)
		}
		sort.Strings(names)
		detectors := make([]PlanDetector, len(names))
		for i, name := range names {
			detectors[i] = planRegistry.detectors[name]
		}
		planRegistry.RUnlock()
		seen := map[string]bool{}
		for _, detect := range detectors {
			plans, e := detect(append([]Entry(nil), listing...), v, n.options)
			if e != nil {
				n.planErr = e
				return
			}
			for _, p := range plans {
				if p == nil || p.ID == "" || p.ID == "." || p.ID == ".." || strings.ContainsAny(p.ID, "/\\\x00") || seen[p.ID] || p.Build == nil {
					n.planErr = fmt.Errorf("invalid or duplicate plan")
					return
				}
				seen[p.ID] = true
				n.proposals = append(n.proposals, p)
				if len(n.proposals) > n.options.MaxEntries {
					n.planErr = ErrLimit
					return
				}
			}
		}
	})
	return append([]*Plan(nil), n.proposals...), n.planErr
}

func (n *Node) planDirectory() (*Node, error) {
	plans, err := n.Plans()
	if err != nil {
		return nil, err
	}
	if len(plans) == 0 {
		return nil, fs.ErrNotExist
	}
	options := n.options
	options.plans = false
	root := Directory("$plans", func() ([]*Node, error) {
		out := make([]*Node, len(plans))
		for i, p := range plans {
			out[i] = FromView(ViewFunc(func() ([]Entry, error) {
				v, err := p.Open()
				if err != nil {
					return nil, err
				}
				return v.Entries()
			}), p.ID, options)
			out[i].attributes = map[string]any{"plan": p.ID, "title": p.Title, "description": p.Description}
		}
		return out, nil
	}, options)
	return root, nil
}
