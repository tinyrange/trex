package uup

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tinyrange/trex/windows/registry"
)

// CSIWinnerValueEdit changes one value relative to a SOFTWARE Winners family.
// Empty Branch means the family key; empty Value.Name means its default value.
// Delete removes only that value, never its key, other values, or subkeys.
// Set operations create the branch when necessary. Data is owned by the result.
type CSIWinnerValueEdit struct {
	Branch string
	Delete bool
	Value  registry.Value
}

type CSIWinnerWritePlan struct {
	Family string
	Change CSIWinnerChange
	Edits  []CSIWinnerValueEdit
}

// PlanCSIWinnerWrites derives minimal value edits from native mark analysis.
// before is the COMPLETE baseline membership of this servicing group; changes
// supplies final membership and impactful-install flags for affected versions.
// current must be the actual branch default (selected branch for functionality
// servicing), not a maximum inferred from membership. Other groups and defaults
// are deliberately not rewritten. This plan does not apply registry edits,
// materialize payloads, or authorize a complete servicing transaction.
func PlanCSIWinnerWrites(identity []byte, current string, before []string, changes []CSIWinnerVersionChange) (CSIWinnerWritePlan, error) {
	if len(before) > 1<<20 || len(changes) > 1<<20 {
		return CSIWinnerWritePlan{}, fmt.Errorf("CSI winner write input exceeds bound")
	}
	family, err := CSIWinnerFamilyKey(identity)
	if err != nil {
		return CSIWinnerWritePlan{}, err
	}
	// Validate baseline branch scope, canonical versions, duplicates, and the
	// effective winner's presence before deriving final membership.
	if _, err := AnalyzeCSIWinnerChange(identity, current, before, nil); err != nil {
		return CSIWinnerWritePlan{}, err
	}
	members := make(map[string]bool, len(before))
	for _, v := range before {
		members[v] = true
	}
	edits := make([]CSIWinnerValueEdit, 0, len(changes)+2)
	for _, delta := range changes {
		was := members[delta.Version]
		if delta.Installed {
			members[delta.Version] = true
		} else {
			delete(members, delta.Version)
		}
		if was == delta.Installed {
			continue
		}
		if _, err := csiWinnerVersion(delta.Version); err != nil {
			return CSIWinnerWritePlan{}, err
		}
		edit := CSIWinnerValueEdit{Branch: csiWinnerBranch(delta.Version), Delete: !delta.Installed, Value: registry.Value{Name: delta.Version}}
		if delta.Installed {
			edit.Value.Type, edit.Value.Data = 3, []byte{1}
		}
		edits = append(edits, edit)
	}
	after := make([]string, 0, len(members))
	for v := range members {
		after = append(after, v)
	}
	change, err := AnalyzeCSIWinnerChange(identity, current, after, changes)
	if err != nil {
		return CSIWinnerWritePlan{}, err
	}
	// Stable membership edit order; all precede winner/default changes.
	sort.Slice(edits, func(i, j int) bool { return edits[i].Value.Name < edits[j].Value.Name })
	id, _ := parseCSIIdentity(identity)
	across := strings.EqualFold(id.VersionScope, "NonSxS") || csiIdentityIsPolicy(id)
	if change.Winner != "" {
		branch := csiWinnerBranch(change.Winner)
		if across {
			edits = append(edits, CSIWinnerValueEdit{Value: csiWinnerString(branch)})
		}
		edits = append(edits, CSIWinnerValueEdit{Branch: branch, Value: csiWinnerString(change.Winner)})
	} else if change.Shadowed != "" {
		if across {
			edits = append(edits, CSIWinnerValueEdit{Delete: true})
		}
		edits = append(edits, CSIWinnerValueEdit{Branch: csiWinnerBranch(change.Shadowed), Delete: true})
	}
	return CSIWinnerWritePlan{Family: family, Change: change, Edits: edits}, nil
}

func csiWinnerBranch(version string) string {
	parts := strings.Split(version, ".")
	return parts[0] + "." + parts[1]
}

func csiWinnerString(version string) registry.Value {
	// Validated version/branch strings contain ASCII decimal digits and dots.
	// REG_SZ includes its terminating UTF-16 NUL, as native SetValue does.
	data := make([]byte, 2*(len(version)+1))
	for i := range version {
		data[2*i] = version[i]
	}
	return registry.Value{Type: 1, Data: data}
}
