package uup

import (
	"fmt"
	"strconv"
	"strings"
)

// CSIWinnerVersionChange describes one exact version after native closure/mark
// analysis. Installed is whether its final installed-mark count is nonzero.
// ImpactfulInstall is the distinct native candidate flag, NOT file presence,
// staging, package selection, or simply a nonzero final installed-mark count.
// Deriving these inputs from deployment closures is a separate operation.
type CSIWinnerVersionChange struct {
	Version          string
	Installed        bool
	ImpactfulInstall bool
}

// CSIWinnerChange is a single native change-list pair. Both strings empty means
// no change. An empty Winner with a Shadowed version means clear the effective
// winner; it does not mean delete all family membership or other branch defaults.
// Setting a Winner updates only its selected major/minor branch default (and,
// for functionality servicing, the family-level branch selector).
type CSIWinnerChange struct {
	Winner   string
	Shadowed string
}

// AnalyzeCSIWinnerChange implements the bounded winner-choice portion of WCP's
// AnalyzeForChangelist. identity is a full CSI identity in the affected family;
// current is its effective winning version, or empty when no winner exists.
// installed lists the COMPLETE membership AFTER install-mark updates, not the
// baseline membership. For ordinary side-by-side identities all inputs must
// have identity's major/minor version; NonSxS and policy identities span branches.
// changes contains exactly the affected versions with final marks and the
// independently established impactful-install flags. All versions are canonical
// four-part uint16 versions. No registry writes or activation are performed.
//
// In particular, this is NOT "pick the highest installed version": a surviving
// winner changes only for a higher impactful install, and an absent winner is
// created only by an impactful install. A removed winner falls back to the
// highest remaining installed member, even when that member was not impactful.
func AnalyzeCSIWinnerChange(identity []byte, current string, installed []string, changes []CSIWinnerVersionChange) (CSIWinnerChange, error) {
	id, err := parseCSIIdentity(identity)
	if err != nil {
		return CSIWinnerChange{}, err
	}
	// Apply the same supported identity alphabet as the native-key machinery.
	if _, err := csiIdentityHash(id, true); err != nil {
		return CSIWinnerChange{}, err
	}
	anchor, err := csiWinnerVersion(id.Version)
	if err != nil {
		return CSIWinnerChange{}, err
	}
	acrossBranches := strings.EqualFold(id.VersionScope, "NonSxS") || csiIdentityIsPolicy(id)
	parse := func(version string) (uint64, error) {
		value, err := csiWinnerVersion(version)
		if err != nil {
			return 0, err
		}
		if !acrossBranches && value>>32 != anchor>>32 {
			return 0, fmt.Errorf("CSI winner version %q is outside the identity's major/minor family", version)
		}
		return value, nil
	}
	members := make(map[uint64]string, len(installed))
	for _, version := range installed {
		value, err := parse(version)
		if err != nil {
			return CSIWinnerChange{}, err
		}
		if _, exists := members[value]; exists {
			return CSIWinnerChange{}, fmt.Errorf("duplicate CSI installed version %q", version)
		}
		members[value] = version
	}
	var old uint64
	if current != "" {
		old, err = parse(current)
		if err != nil {
			return CSIWinnerChange{}, err
		}
	}
	seen := make(map[uint64]bool, len(changes))
	removedCurrent := false
	var candidate uint64
	candidateFound := false
	for _, change := range changes {
		value, err := parse(change.Version)
		if err != nil {
			return CSIWinnerChange{}, err
		}
		if seen[value] {
			return CSIWinnerChange{}, fmt.Errorf("duplicate CSI changed version %q", change.Version)
		}
		seen[value] = true
		_, present := members[value]
		if change.Installed != present {
			return CSIWinnerChange{}, fmt.Errorf("CSI changed version %q disagrees with final installed membership", change.Version)
		}
		if current != "" && value == old && !change.Installed {
			removedCurrent = true
		}
		if change.Installed && change.ImpactfulInstall && (!candidateFound || value > candidate) {
			candidate, candidateFound = value, true
		}
	}
	if current != "" && !removedCurrent {
		if _, present := members[old]; !present {
			return CSIWinnerChange{}, fmt.Errorf("effective CSI winner %q is absent without a corresponding removal", current)
		}
	}
	if current != "" && removedCurrent {
		// Native membership has already been updated before FindNextWinningVersion.
		// Therefore versions removed by this transaction cannot be fallback winners.
		for value := range members {
			if !candidateFound || value > candidate {
				candidate, candidateFound = value, true
			}
		}
		result := CSIWinnerChange{Shadowed: current}
		if candidateFound {
			result.Winner = members[candidate]
		}
		return result, nil
	}
	if candidateFound && (current == "" || candidate > old) {
		return CSIWinnerChange{Winner: members[candidate], Shadowed: current}, nil
	}
	return CSIWinnerChange{}, nil
}

func csiWinnerVersion(text string) (uint64, error) {
	parts := strings.Split(text, ".")
	if len(parts) != 4 {
		return 0, fmt.Errorf("invalid CSI winner version %q", text)
	}
	var result uint64
	for _, part := range parts {
		value, err := strconv.ParseUint(part, 10, 16)
		if err != nil || strconv.FormatUint(value, 10) != part {
			return 0, fmt.Errorf("invalid CSI winner version %q", text)
		}
		result = result<<16 | value
	}
	return result, nil
}
