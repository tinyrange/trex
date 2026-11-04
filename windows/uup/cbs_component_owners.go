package uup

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// CBSComponentOwner identifies one analyzer source and elevation. Anonymous is
// the native null-source RTM placeholder, not the empty source string. Names are
// case-sensitive, and the same source at distinct elevations is distinct.
type CBSComponentOwner struct {
	Name      string
	Elevation uint32
	Anonymous bool
}

// CBSComponentOwnerChange is one cumulative analyzer event. Action is pin,
// unpin, install or uninstall. Pin ownership is separate from installed
// ownership and never supplies self-update applicability by itself.
type CBSComponentOwnerChange struct {
	Owner  CBSComponentOwner
	Action string
}

type CBSComponentOwners struct {
	Installed []CBSComponentOwner
	Pinned    []CBSComponentOwner
}

// ResolveCBSComponentOwners implements the bounded, ordered CalculateNetChanges
// reduction for one already-resolved component version. Changes are the whole
// transaction prefix, NOT a delta applied to an earlier result. Identical
// (source, elevation, action) changes are retained only once, in first-seen
// order. Additions do not replace another elevation or an existing owner.
// Removal requires an exact source/elevation, falling back to an anonymous RTM
// owner when present. A missing removal fails closed. No inventory loading,
// RTM-node synthesis, package reevaluation, CSI persistence or winner selection
// is performed here. Returned arrays are independently owned.
func ResolveCBSComponentOwners(base CBSComponentOwners, changes []CBSComponentOwnerChange) (CBSComponentOwners, error) {
	if len(base.Installed) > 1<<20 || len(base.Pinned) > 1<<20 || len(changes) > 1<<20 || len(base.Installed)+len(base.Pinned)+len(changes) > 1<<20 {
		return CBSComponentOwners{}, fmt.Errorf("CBS component owner count exceeds bound")
	}
	totalBytes := 0
	validate := func(o CBSComponentOwner) error {
		totalBytes += len(o.Name)
		if len(o.Name) > 64<<10 || totalBytes > 64<<20 || !utf8.ValidString(o.Name) || strings.ContainsRune(o.Name, 0) {
			return fmt.Errorf("invalid or oversized CBS component source")
		}
		if o.Anonymous && o.Name != "" {
			return fmt.Errorf("anonymous CBS component source has a name")
		}
		switch o.Elevation &^ 1 {
		case 2, 4, 8, 32, 128:
		default:
			return fmt.Errorf("unsupported CBS component owner elevation %#x", o.Elevation)
		}
		return nil
	}
	for _, owners := range [][]CBSComponentOwner{base.Installed, base.Pinned} {
		for _, owner := range owners {
			if err := validate(owner); err != nil {
				return CBSComponentOwners{}, err
			}
		}
	}
	for _, change := range changes {
		if err := validate(change.Owner); err != nil {
			return CBSComponentOwners{}, err
		}
		// MergeComponentChange always receives a real source string. Null sources
		// are permitted only in the initial inventory (LoadRTMNode).
		if change.Owner.Anonymous {
			return CBSComponentOwners{}, fmt.Errorf("CBS component change requires a named source")
		}
		switch change.Action {
		case "pin", "unpin", "install", "uninstall":
		default:
			return CBSComponentOwners{}, fmt.Errorf("unsupported CBS component change %q", change.Action)
		}
	}
	installed, pinned := newCBSComponentOwnerSet(base.Installed), newCBSComponentOwnerSet(base.Pinned)
	seen := map[CBSComponentOwnerChange]bool{}
	for _, change := range changes {
		if seen[change] {
			continue
		}
		seen[change] = true
		owners := installed
		if change.Action == "pin" || change.Action == "unpin" {
			owners = pinned
		}
		index := owners.find(change.Owner, false)
		if change.Action == "pin" || change.Action == "install" {
			if index < 0 {
				owners.add(change.Owner)
			}
			continue
		}
		if index < 0 {
			index = owners.find(CBSComponentOwner{}, true)
		}
		if index < 0 {
			return CBSComponentOwners{}, fmt.Errorf("CBS component %s source %q elevation %#x has no owner or RTM placeholder", change.Action, change.Owner.Name, change.Owner.Elevation)
		}
		owners.removed[index] = true
	}
	return CBSComponentOwners{Installed: installed.values(), Pinned: pinned.values()}, nil
}

// Stable order with lazy queue heads avoids quadratic scans of large sources.
type cbsComponentOwnerSet struct {
	owners    []CBSComponentOwner
	removed   []bool
	byOwner   map[CBSComponentOwner][]int
	anonymous []int
}

func newCBSComponentOwnerSet(owners []CBSComponentOwner) *cbsComponentOwnerSet {
	s := &cbsComponentOwnerSet{byOwner: map[CBSComponentOwner][]int{}}
	for _, o := range owners {
		s.add(o)
	}
	return s
}
func (s *cbsComponentOwnerSet) add(o CBSComponentOwner) {
	i := len(s.owners)
	s.owners = append(s.owners, o)
	s.removed = append(s.removed, false)
	s.byOwner[o] = append(s.byOwner[o], i)
	if o.Anonymous {
		s.anonymous = append(s.anonymous, i)
	}
}
func (s *cbsComponentOwnerSet) find(o CBSComponentOwner, anonymous bool) int {
	indices := s.byOwner[o]
	if anonymous {
		indices = s.anonymous
	}
	for len(indices) > 0 && s.removed[indices[0]] {
		indices = indices[1:]
	}
	if anonymous {
		s.anonymous = indices
	} else {
		s.byOwner[o] = indices
	}
	if len(indices) == 0 {
		return -1
	}
	return indices[0]
}
func (s *cbsComponentOwnerSet) values() []CBSComponentOwner {
	out := make([]CBSComponentOwner, 0, len(s.owners))
	for i, o := range s.owners {
		if !s.removed[i] {
			out = append(out, o)
		}
	}
	return out
}
