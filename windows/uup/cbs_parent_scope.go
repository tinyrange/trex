package uup

import (
	"fmt"
	"sort"
)

// ParentUpdateScope selects the available package identities searched by
// GetUpdatesFromParentPackages. Comparisons contains one populated runtime
// descriptor per parent block in manifest preorder. This is NOT parent-state
// evaluation: nested rules are alternatives, dispositions and intended states
// are irrelevant, and staged Baseline packages do not relax revision matching.
//
// Only direct references in top-level blocks seed candidates. Exact references
// use exact lookup even with IgnoreRevision. Ranged references collect their
// whole family, then accept candidates matching ANY rule in the parent tree.
// Missing packages are skipped. Results are unique and sorted by exact key;
// this does not reproduce native release-type ordering or enumerate updates.
// Callers must search all direct updates first and recurse only if that entire
// pass finds no matching updates. No input or state cache is modified.
func (index *CBSParentStateIndex) ParentUpdateScope(manifest *AssemblyManifest, comparisons []CBSParentVersionComparison) ([]AssemblyIdentity, error) {
	return index.matchParentIdentities(manifest, comparisons, false)
}

// ParentRelationships selects available identities satisfying IsParent's
// DoesMeetParentRule predicate. Unlike ParentUpdateScope, every root and nested
// rule participates, including nested-only families, and EQ descriptors still
// honor IgnoreRevision. State, disposition and Baseline relaxation do not apply.
// The result is sorted and unique, not native reverse-index enumeration order.
// This predicate alone does not populate a watch list or authorize admission.
func (index *CBSParentStateIndex) ParentRelationships(manifest *AssemblyManifest, comparisons []CBSParentVersionComparison) ([]AssemblyIdentity, error) {
	return index.matchParentIdentities(manifest, comparisons, true)
}

func (index *CBSParentStateIndex) matchParentIdentities(manifest *AssemblyManifest, comparisons []CBSParentVersionComparison, relationships bool) ([]AssemblyIdentity, error) {
	if index == nil || manifest == nil || manifest.Package == nil {
		return nil, fmt.Errorf("CBS parent update scope requires index and package manifest")
	}
	if len(comparisons) != len(manifest.PackageParents) || len(comparisons) > 65536 || len(manifest.References) > 65536 {
		return nil, fmt.Errorf("invalid CBS parent update scope bounds or descriptor count")
	}
	type rule struct {
		identity AssemblyIdentity
		version  [4]uint64
		ops      [3]string
		ignore   bool
		root     bool
	}
	ops := make([][3]string, len(comparisons))
	depths := make([]int, len(comparisons))
	counts := make([]int, len(comparisons))
	for i, parent := range manifest.PackageParents {
		if parent.ParentGroup < 0 || parent.ParentGroup > i {
			return nil, fmt.Errorf("invalid CBS enclosing parent group %d", parent.ParentGroup)
		}
		if parent.ParentGroup != 0 {
			depths[i] = depths[parent.ParentGroup-1] + 1
		}
		if depths[i] > maximumManifestDepth {
			return nil, fmt.Errorf("CBS parent tree exceeds depth bound")
		}
		var err error
		ops[i], err = cbsParentComparisonOperators(comparisons[i])
		if err != nil {
			return nil, err
		}
	}
	var rules []rule
	byFamily := make(map[string][]int)
	for _, ref := range manifest.References {
		if ref.Kind != "parent" {
			continue
		}
		if ref.ParentGroup < 1 || ref.ParentGroup > len(comparisons) {
			return nil, fmt.Errorf("unscoped CBS parent identity %q", ref.Identity.Name)
		}
		if _, err := cbsPackageName(ref.Identity); err != nil {
			return nil, err
		}
		v, err := cbsParentVersion(ref.Identity)
		if err != nil {
			return nil, err
		}
		i := ref.ParentGroup - 1
		counts[i]++
		family := ref.Identity.StableKey()
		byFamily[family] = append(byFamily[family], len(rules))
		rules = append(rules, rule{ref.Identity, v, ops[i], comparisons[i].IgnoreRevision, manifest.PackageParents[i].ParentGroup == 0})
	}
	for i, count := range counts {
		if count == 0 {
			return nil, fmt.Errorf("CBS parent group %d has no direct identities", i+1)
		}
	}
	selected := make(map[string]AssemblyIdentity)
	ranged := make(map[string]bool)
	for _, ref := range rules {
		if !relationships && !ref.root {
			continue
		}
		if !relationships && ref.ops == [3]string{"EQ", "EQ", "EQ"} {
			if c, found := index.exact[ref.identity.ExactKey()]; found {
				selected[c.Identity.ExactKey()] = c.Identity
			}
			continue
		}
		family := ref.identity.StableKey()
		if ranged[family] {
			continue
		}
		ranged[family] = true
		for _, candidate := range index.families[family] {
			for _, r := range byFamily[family] {
				rule := rules[r]
				if cbsParentVersionMatches(candidate.version, rule.version, rule.ops, rule.ignore) {
					selected[candidate.Identity.ExactKey()] = candidate.Identity
					break
				}
			}
		}
	}
	keys := make([]string, 0, len(selected))
	for key := range selected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]AssemblyIdentity, 0, len(keys))
	for _, key := range keys {
		result = append(result, selected[key])
	}
	return result, nil
}
