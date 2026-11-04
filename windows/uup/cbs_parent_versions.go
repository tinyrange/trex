package uup

import (
	"fmt"
	"sort"
	"strings"
)

// CBSParentVersionComparison is an already populated runtime descriptor. Each
// operator must be explicit (EQ, NE, GE, GT, LE, LT). IgnoreRevision is separate
// from the operator: an EQ/EQ/EQ descriptor still takes native exact lookup even
// when this flag is true. Manifest defaults, release-type exceptions and session
// mutations must be resolved by the caller, not guessed from parent presence.
type CBSParentVersionComparison struct {
	MajorMinor, Build, Revision string
	IgnoreRevision              bool
}

// CBSParentCandidate contains effective intended state, not just CurrentState.
// Baseline is the CBS package Baseline attribute, not "came from the base image".
// Pending/session state resolution precedes construction of this immutable index.
type CBSParentCandidate struct {
	Identity      AssemblyIdentity
	IntendedState uint32
	Baseline      bool
}

type cbsParentVersionCandidate struct {
	CBSParentCandidate
	version [4]uint64
}

// CBSParentStateIndex provides deterministic related-version queries over a
// transaction-state snapshot. Rebuild it after changing effective intents.
type CBSParentStateIndex struct {
	exact    map[string]cbsParentVersionCandidate
	families map[string][]cbsParentVersionCandidate
}

func resolvedCBSParentState(state uint32) bool {
	switch state {
	case CBSStateAbsent, 0x20, CBSStateStaged, 0x50, CBSStateInstalled, 0x80:
		return true
	}
	return false
}

func cbsParentVersion(id AssemblyIdentity) ([4]uint64, error) {
	v, ok := assemblyVersionParts(id.Version)
	if !ok {
		return v, fmt.Errorf("invalid CBS parent version %q", id.Version)
	}
	for _, n := range v {
		if n > 0xffff {
			return v, fmt.Errorf("CBS parent version field exceeds WORD: %q", id.Version)
		}
	}
	return v, nil
}

func NewCBSParentStateIndex(candidates []CBSParentCandidate) (*CBSParentStateIndex, error) {
	index := &CBSParentStateIndex{exact: map[string]cbsParentVersionCandidate{}, families: map[string][]cbsParentVersionCandidate{}}
	for _, c := range candidates {
		if _, err := cbsPackageName(c.Identity); err != nil {
			return nil, err
		}
		v, err := cbsParentVersion(c.Identity)
		if err != nil {
			return nil, err
		}
		if !resolvedCBSParentState(c.IntendedState) {
			return nil, fmt.Errorf("unresolved CBS parent intended state %#x", c.IntendedState)
		}
		key := c.Identity.ExactKey()
		if _, exists := index.exact[key]; exists {
			return nil, fmt.Errorf("duplicate CBS parent identity %q", c.Identity.Name)
		}
		entry := cbsParentVersionCandidate{CBSParentCandidate: c, version: v}
		index.exact[key] = entry
		family := c.Identity.StableKey()
		index.families[family] = append(index.families[family], entry)
	}
	for _, family := range index.families {
		sort.Slice(family, func(i, j int) bool {
			for n := range family[i].version {
				if family[i].version[n] != family[j].version[n] {
					return family[i].version[n] > family[j].version[n]
				}
			}
			return family[i].Identity.ExactKey() < family[j].Identity.ExactKey()
		})
	}
	return index, nil
}

func cbsParentCompare(actual, wanted uint64, op string) bool {
	switch op {
	case "EQ":
		return actual == wanted
	case "NE":
		return actual != wanted
	case "GE":
		return actual >= wanted
	case "GT":
		return actual > wanted
	case "LE":
		return actual <= wanted
	case "LT":
		return actual < wanted
	}
	return false
}

// Resolve implements GetParentIntendedState's exact/range lookup on the supplied
// effective-state snapshot. It never changes the caller's descriptor or index.
// Range lookup is descending and relaxes revision only AFTER a matching staged
// Baseline candidate; it does not restart at higher, previously rejected versions.
func (index *CBSParentStateIndex) Resolve(reference AssemblyIdentity, descriptor CBSParentVersionComparison) (uint32, error) {
	if index == nil {
		return 0, fmt.Errorf("nil CBS parent state index")
	}
	if _, err := cbsPackageName(reference); err != nil {
		return 0, err
	}
	wanted, err := cbsParentVersion(reference)
	if err != nil {
		return 0, err
	}
	ops, err := cbsParentComparisonOperators(descriptor)
	if err != nil {
		return 0, err
	}
	if ops[0] == "EQ" && ops[1] == "EQ" && ops[2] == "EQ" {
		return index.exact[reference.ExactKey()].IntendedState, nil
	}
	ignoreRevision := descriptor.IgnoreRevision
	var state uint32
	for _, candidate := range index.families[reference.StableKey()] {
		if !cbsParentVersionMatches(candidate.version, wanted, ops, ignoreRevision) {
			continue
		}
		if candidate.Baseline && candidate.IntendedState == CBSStateStaged {
			ignoreRevision = true
		}
		state = max(state, candidate.IntendedState)
		if state >= CBSStateInstalled {
			break
		}
	}
	return state, nil
}

func cbsParentComparisonOperators(descriptor CBSParentVersionComparison) ([3]string, error) {
	ops := [3]string{strings.ToUpper(descriptor.MajorMinor), strings.ToUpper(descriptor.Build), strings.ToUpper(descriptor.Revision)}
	for _, op := range ops {
		switch op {
		case "EQ", "NE", "GE", "GT", "LE", "LT":
		default:
			return ops, fmt.Errorf("unsupported CBS parent comparison %q", op)
		}
	}
	return ops, nil
}

// EvaluateVersionCompare continues only on successful equality. An unequal
// successful higher dimension wins; strict comparisons fail on equality.
// Exact-lookup dispatch belongs to the caller, not this predicate.
func cbsParentVersionMatches(actual, wanted [4]uint64, ops [3]string, ignoreRevision bool) bool {
	av := [3]uint64{actual[0]<<16 | actual[1], actual[2], actual[3]}
	wv := [3]uint64{wanted[0]<<16 | wanted[1], wanted[2], wanted[3]}
	for dimension, op := range ops {
		if dimension == 2 && ignoreRevision {
			return true
		}
		matches := cbsParentCompare(av[dimension], wv[dimension], op)
		if !matches || av[dimension] != wv[dimension] {
			return matches
		}
	}
	return true
}
