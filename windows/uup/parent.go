package uup

import (
	"fmt"
	"strconv"
	"strings"
)

// parentIdentityMatches applies the explicit package version predicates without
// relaxing publisher, architecture, language or major/minor release identity.
// Revision-only wrappers retain the parent's build and accept revisions at or
// above their checkpoint. A build-only predicate leaves revision unconstrained.
// Comparison is lexicographic: a successful unequal build comparison decides
// the result without consulting revision. This is the explicit predicate check,
// not CBS transaction parent resolution (which also applies package policy and
// distinguishes baseline states from execution intents).
func parentIdentityMatches(reference AssemblyReference, installed AssemblyIdentity) bool {
	if installed.StableKey() != reference.Identity.StableKey() {
		return false
	}
	build, revision := parentVersionComparisons(reference)
	if build == "" && revision == "" {
		return installed.ExactKey() == reference.Identity.ExactKey()
	}
	wanted, ok := assemblyVersionParts(reference.Identity.Version)
	if !ok {
		return false
	}
	actual, ok := assemblyVersionParts(installed.Version)
	if !ok || actual[0] != wanted[0] || actual[1] != wanted[1] {
		return false
	}
	if build == "" {
		build = "EQ"
	}
	matches := func(have, want uint64, op string) bool {
		switch op {
		case "EQ":
			return have == want
		case "GE":
			return have >= want
		}
		return false
	}
	if !matches(actual[2], wanted[2], build) {
		return false
	}
	if actual[2] != wanted[2] {
		return true
	}
	return revision == "" || matches(actual[3], wanted[3], revision)
}

func parentVersionComparisons(reference AssemblyReference) (string, string) {
	build, revision := "", ""
	for _, a := range reference.Attributes {
		switch a.Name {
		case "buildCompare":
			build = strings.ToUpper(a.Value)
		case "revisionCompare":
			revision = strings.ToUpper(a.Value)
		}
	}
	return build, revision
}

// Keep every version: a build-EQ parent can match an older installed version
// even when the family's newest version belongs to another build.
func (state *assemblyImageState) rememberPackage(identity AssemblyIdentity) {
	exact := identity.ExactKey()
	if _, exists := state.packagesByExact[exact]; !exists {
		stable := identity.StableKey()
		state.packagesByStable[stable] = append(state.packagesByStable[stable], identity)
	}
	state.packagesByExact[exact] = identity
}

func (state *assemblyImageState) hasInstalledParent(reference AssemblyReference) bool {
	build, revision := parentVersionComparisons(reference)
	if build == "" && revision == "" {
		return state.hasInstalledIdentity(reference.Identity)
	}
	for _, installed := range state.packagesByStable[reference.Identity.StableKey()] {
		if parentIdentityMatches(reference, installed) {
			return true
		}
	}
	return false
}

func assemblyVersionParts(version string) ([4]uint64, bool) {
	var result [4]uint64
	if strings.Count(version, ".") != 3 {
		return result, false
	}
	for i := range result {
		s, rest, _ := strings.Cut(version, ".")
		version = rest
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return result, false
		}
		result[i] = n
	}
	return result, true
}

// CBS servicing-stack aggregate names embed the servicing revision, unlike
// ordinary package stable keys. Older checkpoint SSUs remain content sources
// but must never reinstall themselves over an already newer stack.
func (state *assemblyImageState) hasSupersedingServicingStack(wanted AssemblyIdentity) bool {
	family := func(id AssemblyIdentity) string {
		const prefix = "package_for_servicingstack_"
		name := strings.ToLower(id.Name)
		if !strings.HasPrefix(name, prefix) {
			return ""
		}
		if _, err := strconv.ParseUint(strings.TrimPrefix(name, prefix), 10, 32); err != nil {
			return ""
		}
		id.Name = prefix
		return id.StableKey()
	}
	key := family(wanted)
	if key == "" {
		return false
	}
	for _, installed := range state.packagesByExact {
		if family(installed) == key && compareVersions(installed.Version, wanted.Version) >= 0 {
			return true
		}
	}
	return false
}

// Reject unsupported comparison semantics before planning rather than silently
// treating a potentially applicable package as absent.
func validateParentComparisons(manifest *AssemblyManifest) error {
	for _, ref := range manifest.References {
		if ref.Kind != "parent" {
			continue
		}
		for _, a := range ref.Attributes {
			switch a.Name {
			case "buildCompare":
				if a.Value != "" && !strings.EqualFold(a.Value, "EQ") && !strings.EqualFold(a.Value, "GE") {
					return fmt.Errorf("unsupported parent buildCompare %q", a.Value)
				}
			case "revisionCompare":
				if a.Value != "" && !strings.EqualFold(a.Value, "EQ") && !strings.EqualFold(a.Value, "GE") {
					return fmt.Errorf("unsupported parent revisionCompare %q", a.Value)
				}
			}
		}
	}
	return nil
}

// Checkpoint LCUs remain available as content sources but cannot install their
// aggregate over a newer package of the same stable identity. SSU aggregates
// additionally encode the revision in their name and need family normalization.
func (state *assemblyImageState) hasSupersedingAggregate(wanted AssemblyIdentity) bool {
	if installed, ok := state.latestPackageByStable[wanted.StableKey()]; ok && compareVersions(installed.Version, wanted.Version) >= 0 {
		return true
	}
	return state.hasSupersedingServicingStack(wanted)
}
