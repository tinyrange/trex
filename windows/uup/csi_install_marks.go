package uup

import (
	"fmt"
	"sort"
	"strings"
)

// CSIInstallMarkDeployment supplies an exact composition and the complete set
// of baseline i!CBS_ source payloads on that deployment. Sources are native
// two-length records, not source key names or package activation booleans.
// Changed compositions must come from CalculateCSIComposition. Unchanged
// deployments may instead supply persisted c! membership. Include every resident owner, even when
// its sources are unchanged, and all deployments with changed installed sources.
// Non-CBS source inventories require a separate source policy.
type CSIInstallMarkDeployment struct {
	Identity         AssemblyIdentity
	Composition      []CSICompositionMember
	InstalledSources [][]byte
	// PersistedMembers is the installed c! membership inventory for an
	// unchanged deployment. Non-nil excludes Composition, carries no impact
	// dispositions, and is rejected for any install/uninstall action.
	PersistedMembers []AssemblyIdentity
}

// CSIComponentInstallMarks describes source-count analysis, not persistence.
// Affected includes uninstall closures even when another source keeps the
// component installed. ImpactfulInstall is independent of the final count.
type CSIComponentInstallMarks struct {
	Identity         AssemblyIdentity
	Initial          uint32
	Final            uint32
	Affected         bool
	ImpactfulInstall bool
}

// AnalyzeCSIInstallMarks sums installed sources through exact compositions,
// then applies ordinary CBS install/uninstall source transitions. Each source
// contributes one mark to each member; counting merely active deployments loses
// shared-source references. Source presence is checked before every transition.
// Duplicate changes are rejected rather than interpreted as reexecution.
//
// Stage-only and unchanged actions do not affect install marks. Driver actions
// participate in this analysis but still require the separate native driver
// operation queue: this result neither executes that queue nor authorizes a
// component-only commit. No source payloads, backlinks, winners or files are
// written. Input completeness is the caller's obligation; omitted owners cannot
// be inferred from the changed deployment list.
func AnalyzeCSIInstallMarks(inventory []CSIInstallMarkDeployment, actions []CBSDeploymentAction) ([]CSIComponentInstallMarks, error) {
	const workLimit = 1 << 22
	if len(inventory) > 1<<20 || len(actions) > 1<<20 {
		return nil, fmt.Errorf("CSI install-mark input bound exceeded")
	}
	type deploymentState struct {
		members      []string
		dispositions []uint32
		sources      map[string]bool
		persisted    bool
	}
	deployments := make(map[string]*deploymentState, len(inventory))
	marks := make(map[string]*CSIComponentInstallMarks)
	work := 0
	for _, deployment := range inventory {
		key, err := compositionIdentityKey(deployment.Identity)
		if err != nil {
			return nil, err
		}
		if _, exists := deployments[key]; exists {
			return nil, fmt.Errorf("duplicate CSI install-mark deployment %q", deployment.Identity.Name)
		}
		state := &deploymentState{sources: make(map[string]bool), persisted: deployment.PersistedMembers != nil}
		deployments[key] = state
		for _, data := range deployment.InstalledSources {
			work++
			if work > workLimit {
				return nil, fmt.Errorf("CSI install-mark work bound exceeded")
			}
			source, err := ParseCBSDeploymentSource(data)
			if err != nil {
				return nil, err
			}
			sourceKey := strings.ToLower(source.Primary)
			if state.sources[sourceKey] {
				return nil, fmt.Errorf("duplicate installed CSI source %q", source.Primary)
			}
			state.sources[sourceKey] = true
		}
		members := deployment.Composition
		if state.persisted {
			if members != nil {
				return nil, fmt.Errorf("CSI persisted membership cannot also supply a composition")
			}
			members = make([]CSICompositionMember, len(deployment.PersistedMembers))
			for i, identity := range deployment.PersistedMembers {
				members[i].Identity = identity
			}
		}
		seen := make(map[string]bool)
		root := false
		for _, member := range members {
			work++
			if work > workLimit {
				return nil, fmt.Errorf("CSI install-mark work bound exceeded")
			}
			memberKey, err := compositionIdentityKey(member.Identity)
			if err != nil {
				return nil, err
			}
			if seen[memberKey] {
				return nil, fmt.Errorf("duplicate CSI composition member %q", member.Identity.Name)
			}
			seen[memberKey] = true
			if !state.persisted && member.Disposition != 1 && member.Disposition != 2 {
				return nil, fmt.Errorf("invalid CSI composition disposition")
			}
			if memberKey == key {
				root = true
				if !state.persisted && member.Disposition != 2 {
					return nil, fmt.Errorf("CSI composition root must have install disposition")
				}
			}
			state.members = append(state.members, memberKey)
			state.dispositions = append(state.dispositions, member.Disposition)
			mark := marks[memberKey]
			if mark == nil {
				identity := member.Identity
				identity.Attributes = append([]ManifestAttribute(nil), identity.Attributes...)
				mark = &CSIComponentInstallMarks{Identity: identity}
				marks[memberKey] = mark
			}
			if uint64(mark.Initial)+uint64(len(state.sources)) > uint64(^uint32(0)) {
				return nil, fmt.Errorf("CSI installed-mark overflow")
			}
			mark.Initial += uint32(len(state.sources))
			mark.Final = mark.Initial
		}
		if !root && (!state.persisted || len(members) != 0 || len(state.sources) != 0) {
			return nil, fmt.Errorf("CSI install-mark composition lacks its exact root")
		}
	}
	seenChanges := make(map[string]bool)
	for _, action := range actions {
		if action.Action == CBSActionNone {
			continue
		}
		if action.Action != CBSActionInstall && action.Action != CBSActionUninstall {
			return nil, fmt.Errorf("unsupported CSI install-mark action %d", action.Action)
		}
		key, err := compositionIdentityKey(action.Deployment)
		if err != nil {
			return nil, err
		}
		state := deployments[key]
		if state == nil {
			return nil, fmt.Errorf("missing exact CSI install-mark deployment %q", action.Deployment.Name)
		}
		if state.persisted {
			return nil, fmt.Errorf("CSI changed deployment requires a manifest-derived composition, not persisted membership")
		}
		data, err := marshalCBSDeploymentSource(cbsDeploymentSource{Package: action.Package, Update: action.UpdateName}, nil)
		if err != nil {
			return nil, err
		}
		source, err := ParseCBSDeploymentSource(data)
		if err != nil {
			return nil, err
		}
		sourceKey := strings.ToLower(source.Primary)
		changeKey := key + "\x00" + sourceKey
		if seenChanges[changeKey] {
			return nil, fmt.Errorf("duplicate CSI installed-source change %q", source.Primary)
		}
		seenChanges[changeKey] = true
		install := action.Action == CBSActionInstall
		if state.sources[sourceKey] == install {
			return nil, fmt.Errorf("CSI installed-source presence disagrees with action for %q", source.Primary)
		}
		state.sources[sourceKey] = install
		for i, memberKey := range state.members {
			work++
			if work > workLimit {
				return nil, fmt.Errorf("CSI install-mark work bound exceeded")
			}
			mark := marks[memberKey]
			mark.Affected = true
			// GenerateServicingFamilies sets the flag before testing install vs
			// uninstall. A still-installed member of an uninstall closure can
			// therefore be an impactful winner candidate.
			mark.ImpactfulInstall = mark.ImpactfulInstall || state.dispositions[i] == 2 || csiIdentityIsPolicy(mark.Identity)
			if install {
				if mark.Final == ^uint32(0) {
					return nil, fmt.Errorf("CSI installed-mark overflow")
				}
				mark.Final++
			} else {
				if mark.Final == 0 {
					return nil, fmt.Errorf("CSI installed-mark underflow")
				}
				mark.Final--
			}
		}
	}
	keys := make([]string, 0, len(marks))
	for key := range marks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]CSIComponentInstallMarks, 0, len(keys))
	for _, key := range keys {
		result = append(result, *marks[key])
	}
	return result, nil
}

// WCP IsIdentityPolicy/GetFunctionalityServicing accept "policy" and a type
// ending in "-policy", but explicitly exclude the bare suffix "-policy".
func csiIdentityIsPolicy(id AssemblyIdentity) bool {
	for _, attribute := range id.Attributes {
		if attribute.Namespace == "" && strings.EqualFold(attribute.Name, "type") {
			kind := strings.ToLower(attribute.Value)
			return kind == "policy" || (kind != "-policy" && strings.HasSuffix(kind, "-policy"))
		}
	}
	return false
}
