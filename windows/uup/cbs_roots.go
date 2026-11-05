package uup

import (
	"fmt"
	"strings"
)

// CBSRootPackageIntent describes an explicit stage/install package action, not
// a package merely encountered while expanding references. Owners must be the
// effective persisted/session owner values in native enumeration order, with
// session overrides already applied. The resolver neither reads a registry nor
// derives the CBSBLR runtime feature policy from a package's manifest.
type CBSRootPackageIntent struct {
	Identity      AssemblyIdentity
	IntendedState uint32
	Integration   uint32
	ExplicitOwner string
	Owners        []CBSPackageOwnerIntent
	CBSBLREnabled bool
}

// PlanCBSRootPackageOwner resolves the extra owner supplied by an explicit
// package action. A nil result is valid: a package owned only by ordinary
// containing packages does not acquire a self owner just because it was a root
// action. Ownerless packages, existing self owners (regardless of their state),
// and liberated owners are self-owned for this decision. With CBSBLR enabled,
// native planning preserves the liberated owner name and integration instead
// of projecting it to self. The input order matters when several liberated
// owners exist. An explicit owner takes precedence over this fallback.
//
// Only additive stage/install actions are supported. This does not implement
// update-only (0x1000), removal, permanence, owner merging or final CurrentState.
func PlanCBSRootPackageOwner(in CBSRootPackageIntent) (*CBSPackageOwnerIntent, error) {
	name, err := cbsPackageName(in.Identity)
	if err != nil {
		return nil, err
	}
	if in.IntendedState != CBSStateStaged && in.IntendedState != CBSStateInstalled {
		return nil, fmt.Errorf("unsupported CBS root intent %#x", in.IntendedState)
	}
	if in.Integration < 2 || in.Integration > 4 {
		return nil, fmt.Errorf("unsupported CBS root integration %d", in.Integration)
	}
	validateOwner := func(owner string) error {
		id, err := ParsePackageManifestName(owner + ".mum")
		if err != nil {
			return fmt.Errorf("invalid CBS root owner %q: %w", owner, err)
		}
		canonical, err := cbsPackageName(id)
		if err != nil || !strings.EqualFold(canonical, owner) {
			return fmt.Errorf("invalid CBS root owner %q", owner)
		}
		return nil
	}
	if in.ExplicitOwner != "" {
		if err := validateOwner(in.ExplicitOwner); err != nil {
			return nil, err
		}
	}
	seen := make(map[string]bool, len(in.Owners))
	for _, o := range in.Owners {
		if !strings.EqualFold(o.Package, name) {
			return nil, fmt.Errorf("CBS root owner belongs to another package %q", o.Package)
		}
		if err := validateOwner(o.Owner); err != nil {
			return nil, err
		}
		key := strings.ToLower(o.Owner)
		if seen[key] {
			return nil, fmt.Errorf("duplicate CBS root owner %q", o.Owner)
		}
		seen[key] = true
		if o.Integration < 2 || o.Integration > 4 || o.State > 0xffff {
			return nil, fmt.Errorf("unsupported CBS root owner value for %q", o.Owner)
		}
	}
	owner, integration := in.ExplicitOwner, in.Integration
	if owner == "" {
		selfOwned := len(in.Owners) == 0
		preserved, preservedIntegration := name, uint32(2)
		for _, o := range in.Owners {
			if strings.EqualFold(o.Owner, name) {
				selfOwned = true
				preserved, preservedIntegration = name, o.Integration
				break
			}
			if o.Integration == 4 {
				selfOwned = true
				preserved, preservedIntegration = o.Owner, o.Integration
			}
		}
		if !selfOwned {
			return nil, nil
		}
		owner = name
		if in.CBSBLREnabled {
			owner, integration = preserved, preservedIntegration
		}
	}
	return &CBSPackageOwnerIntent{Package: name, Owner: owner, Integration: integration, State: in.IntendedState}, nil
}
