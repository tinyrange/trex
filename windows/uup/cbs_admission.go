package uup

import (
	"fmt"
	"strings"
)

// CBSPackageAdmission supplies one ordinary AddPackage state calculation.
// StoreOwners are the effective persisted/session-store owners, before execution
// overlays. ExecutionOwners are the current named owners of one execution item,
// not a history of all previous requests. Both lists must have unique names.
// The caller must resolve pending states and package applicability first.
//
// This is the ordinary owner/applicability path, not the force-state,
// capability-wrapper, unresolved-applicability or multiple-execution-item paths.
// It does not merge execution items, process MUMs, schedule dependents or persist
// package/owner states. In particular IntendedState is not final CurrentState.
type CBSPackageAdmission struct {
	Identity        AssemblyIdentity
	StoreOwners     []CBSPackageOwnerIntent
	ExecutionOwners []CBSPackageOwnerIntent
	Owner           string
	RequestedState  uint32
	Ceiling         uint32
	ApplicableState uint32

	// PreserveStoreOwner corresponds to AddPackage flag 0x40: raise the named
	// request to the effective store owner's state, not its execution overlay.
	PreserveStoreOwner bool
	// BypassOwners uses the request directly instead of aggregating owners.
	// It does not bypass the caller ceiling or package applicability.
	BypassOwners bool
}

// CBSAdmissionState keeps distinct values that native execution uses for
// different purposes. EffectiveRequest is the per-owner request (possibly
// raised by PreserveStoreOwner). OwnerState includes other owners; CappedState
// additionally applies the caller ceiling. IntendedState applies applicability.
// Never write IntendedState into every owner: an installed/permanent owner may
// coexist with a staged/superseded package target.
type CBSAdmissionState struct {
	EffectiveRequest uint32
	OwnerState       uint32
	CappedState      uint32
	IntendedState    uint32
}

// ResolveCBSPackageAdmission reduces one already-resolved ordinary admission.
// Named execution owners replace store values; a concrete named request then
// replaces that owner's value again. MAX is only across different effective
// owners, not across historical requests. An ownerless concrete request is a
// fallback only when there are no owners. The unspecified ownerless watch-list
// request contributes no owner and returns absent for an ownerless package.
//
// The function is pure and rejects unresolved state rather than guessing an
// install/removal action. It does not imply that a zero-state result authorizes
// removal. See the native AddPackage/CalculateAllOwnersIntendedState evidence in
// docs/formats/csi-offline-state.md.
func ResolveCBSPackageAdmission(in CBSPackageAdmission) (*CBSAdmissionState, error) {
	name, err := cbsPackageName(in.Identity)
	if err != nil {
		return nil, err
	}
	return resolveCBSPackageAdmission(in, name, validateCBSAdmissionOwnerName)
}

func validateCBSAdmissionOwnerName(owner string) error {
	id, err := ParsePackageManifestName(owner + ".mum")
	if err != nil {
		return fmt.Errorf("invalid CBS admission owner %q: %w", owner, err)
	}
	canonical, err := cbsPackageName(id)
	if err != nil || !strings.EqualFold(owner, canonical) {
		return fmt.Errorf("invalid CBS admission owner %q", owner)
	}
	return nil
}

func resolveCBSPackageAdmission(in CBSPackageAdmission, name string, validateName func(string) error) (*CBSAdmissionState, error) {
	if in.Owner != "" {
		if err := validateName(in.Owner); err != nil {
			return nil, err
		}
		if in.RequestedState == CBSStateUnspecified {
			return nil, fmt.Errorf("CBS admission has an unspecified named owner request")
		}
	}
	if !resolvedCBSParentState(in.RequestedState) && in.RequestedState != CBSStateUnspecified {
		return nil, fmt.Errorf("unresolved CBS admission request %#x", in.RequestedState)
	}
	if !resolvedCBSParentState(in.Ceiling) && in.Ceiling != CBSStateUnspecified {
		return nil, fmt.Errorf("unresolved CBS admission ceiling %#x", in.Ceiling)
	}
	if !resolvedCBSParentState(in.ApplicableState) {
		return nil, fmt.Errorf("unresolved CBS admission applicability %#x", in.ApplicableState)
	}
	if in.BypassOwners && in.RequestedState == CBSStateUnspecified {
		return nil, fmt.Errorf("CBS owner bypass requires a concrete request")
	}
	if len(in.StoreOwners) > 1<<16 || len(in.ExecutionOwners) > 1<<16 {
		return nil, fmt.Errorf("CBS admission owners exceed bound")
	}
	owners := make(map[string]uint32, len(in.StoreOwners)+len(in.ExecutionOwners)+1)
	request := in.RequestedState
	for layer, values := range [][]CBSPackageOwnerIntent{in.StoreOwners, in.ExecutionOwners} {
		seen := make(map[string]bool, len(values))
		for _, owner := range values {
			if !strings.EqualFold(owner.Package, name) {
				return nil, fmt.Errorf("CBS admission owner belongs to another package %q", owner.Package)
			}
			if err := validateName(owner.Owner); err != nil {
				return nil, err
			}
			if owner.Integration < 2 || owner.Integration > 4 || !resolvedCBSParentState(owner.State) {
				return nil, fmt.Errorf("unsupported CBS admission owner value for %q", owner.Owner)
			}
			key := strings.ToLower(owner.Owner)
			if seen[key] {
				return nil, fmt.Errorf("duplicate CBS admission owner %q in layer %d", owner.Owner, layer)
			}
			seen[key] = true
			owners[key] = owner.State
			if layer == 0 && in.PreserveStoreOwner && in.Owner != "" && strings.EqualFold(owner.Owner, in.Owner) {
				request = max(request, owner.State)
			}
		}
	}
	if in.Owner != "" {
		owners[strings.ToLower(in.Owner)] = request
	}
	var state uint32
	if in.BypassOwners {
		state = request
	} else {
		for _, value := range owners {
			state = max(state, value)
		}
		if len(owners) == 0 && request != CBSStateUnspecified {
			state = request
		}
		state = min(state, CBSStateInstalled)
	}
	capped := state
	if in.Ceiling != CBSStateUnspecified {
		capped = min(capped, in.Ceiling)
	}
	return &CBSAdmissionState{
		EffectiveRequest: request,
		OwnerState:       state,
		CappedState:      capped,
		IntendedState:    min(capped, in.ApplicableState),
	}, nil
}
