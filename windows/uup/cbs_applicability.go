package uup

import "fmt"

const CBSStateSuperseded uint32 = 0x50

// CBSApplicability supplies already resolved package/session policy. ParentState
// is the parsed parent-tree result, including the no-parent sentinel. BranchMatches
// is true when the package has no branch constraint or its constraint matched.
// ForceStageSuperseded is the conjunction of the native package and session
// force-staging flags, not a generic rule that all old packages remain staged.
type CBSApplicability struct {
	ParentState          uint32
	BranchMatches        bool
	ForceStageSuperseded bool
}

// ApplicableState implements uncached CBS package applicability over this
// immutable effective-intent snapshot. It does not return final CurrentState:
// owner intent and transaction caps still constrain the resulting target.
// Only strictly newer versions of the same package family with intended state
// above superseded suppress installation. Equal/older versions, staged newer
// packages and the Baseline attribute do not do so. Parent revision-ignore
// policy does not affect this full four-part version comparison.
func (index *CBSParentStateIndex) ApplicableState(identity AssemblyIdentity, policy CBSApplicability) (uint32, error) {
	if index == nil {
		return 0, fmt.Errorf("nil CBS state index")
	}
	if _, err := cbsPackageName(identity); err != nil {
		return 0, err
	}
	version, err := cbsParentVersion(identity)
	if err != nil {
		return 0, err
	}
	if policy.ParentState != CBSStateUnspecified && !resolvedCBSParentState(policy.ParentState) {
		return 0, fmt.Errorf("unresolved CBS applicability parent state %#x", policy.ParentState)
	}
	if !policy.BranchMatches {
		return CBSStateAbsent, nil
	}
	state := policy.ParentState
	if state == CBSStateUnspecified {
		state = CBSStateInstalled
	}
	if state < CBSStateInstalled {
		return state, nil
	}
	for _, candidate := range index.families[identity.StableKey()] {
		newer := false
		for i, part := range candidate.version {
			if part != version[i] {
				newer = part > version[i]
				break
			}
		}
		// Families are sorted descending; all subsequent versions are also <=.
		if !newer {
			break
		}
		if candidate.IntendedState > CBSStateSuperseded {
			if policy.ForceStageSuperseded {
				return CBSStateStaged, nil
			}
			return CBSStateSuperseded, nil
		}
	}
	return state, nil
}
