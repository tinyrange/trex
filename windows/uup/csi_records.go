package uup

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/tinyrange/trex/storage"
)

// CSIComponentRecord describes a newly materialized, uncompressed component.
// It is NOT a complete servicing transaction. Existing component records must
// not be replaced by this description: their physical storage flags, existing
// owners and retirement state remain valid independently of this stage.
type CSIComponentRecord struct {
	Stem           string
	Identity       []byte
	ManifestSHA256 [sha256.Size]byte
	Files          []CSIFileRecord
}

type CSIFileRecord struct {
	Name  string
	Flags uint32
}

// CSIComponentOwner is an additive empty REG_BINARY c! value on an exact
// component, including components already resident in the image.
type CSIComponentOwner struct {
	Stem string
	Name string
}

type CSIComponentStatePlan struct {
	Components []CSIComponentRecord
	Owners     []CSIComponentOwner
}

// PlanCSIComponentState constructs the component portion of CSI state from
// decoded manifests and the resolved ownership graph. It neither applies the
// result nor sets package/deployment activation or supersedence. Payloads must
// be materialized and verified separately; Files describes their final RAW
// storage, not the PSFX transport encoding. No reverse/null sidecars or physical
// compression flags are claimed when only the reconstructed file is retained.
func PlanCSIComponentState(stage *CumulativeStage, plan StageAssemblyPlan) (CSIComponentStatePlan, error) {
	if stage == nil {
		return CSIComponentStatePlan{}, fmt.Errorf("CSI component state requires a stage")
	}
	return planCSIComponentState(plan, stage.openAssemblyFile, stage.releaseAssemblyFile)
}

// PlanCSIComponentDescriptions describes only explicitly selected raw store
// components. It makes no claim about deployment ownership or installation;
// callers must join the complete composition/source graph separately.
func PlanCSIComponentDescriptions(stage *CumulativeStage, components []PlannedComponent) ([]CSIComponentRecord, error) {
	if stage == nil {
		return nil, fmt.Errorf("CSI component descriptions require a stage")
	}
	return planCSIComponentDescriptions(components, stage.openAssemblyFile, stage.releaseAssemblyFile)
}

func planCSIComponentDescriptions(components []PlannedComponent, open func(string) (storage.Reader, error), release func(string)) ([]CSIComponentRecord, error) {
	result := []CSIComponentRecord{}
	selected := make(map[string]bool)
	for _, component := range components {
		key := strings.ToLower(component.Stem)
		if selected[key] {
			return nil, fmt.Errorf("duplicate CSI component %q", component.Stem)
		}
		selected[key] = true
		if err := validateCSIComponentStem(component); err != nil {
			return nil, err
		}
		parsed, err := openPlannedManifest(component, open, release)
		if err != nil {
			return nil, err
		}
		manifest := parsed.Manifest()
		if manifest.Identity.ExactKey() != component.Identity.ExactKey() {
			return nil, fmt.Errorf("CSI manifest identity mismatch for %q", component.Stem)
		}
		// ExactKey intentionally omits some CSI attributes; validate the complete
		// manifest identity against the cryptographic-independent CSI name hash too.
		actual := component
		actual.Identity = manifest.Identity
		if err := validateCSIComponentStem(actual); err != nil {
			return nil, err
		}
		identity, err := marshalCSIIdentity(manifest.Identity)
		if err != nil {
			return nil, err
		}
		record := CSIComponentRecord{Stem: component.Stem, Identity: identity}
		record.ManifestSHA256 = sha256.Sum256([]byte(parsed.data))
		names := make(map[string]bool)
		for _, file := range manifest.Files {
			if _, err := componentSourcePath(file); err != nil {
				return nil, err
			}
			name, err := csiFileKey(file.Name)
			if err != nil {
				return nil, err
			}
			if names[name] {
				return nil, fmt.Errorf("duplicate CSI file record %q", name)
			}
			names[name] = true
			record.Files = append(record.Files, CSIFileRecord{Name: name, Flags: 1})
		}
		sort.Slice(record.Files, func(i, j int) bool { return record.Files[i].Name < record.Files[j].Name })
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool { return strings.ToLower(result[i].Stem) < strings.ToLower(result[j].Stem) })
	return result, nil
}

func planCSIComponentState(plan StageAssemblyPlan, open func(string) (storage.Reader, error), release func(string)) (CSIComponentStatePlan, error) {
	components, err := planCSIComponentDescriptions(plan.Components, open, release)
	if err != nil {
		return CSIComponentStatePlan{}, err
	}
	result := CSIComponentStatePlan{Components: components}
	selected := make(map[string]bool)
	for _, component := range components {
		selected[strings.ToLower(component.Stem)] = true
	}
	seenOwners := make(map[string]bool)
	owned := make(map[string]bool)
	for _, deployment := range plan.Deployments {
		name, err := csiDeploymentKey(deployment.Identity)
		if err != nil {
			return CSIComponentStatePlan{}, err
		}
		root := false
		for _, component := range deployment.Components {
			if err := validateCSIComponentStem(component); err != nil {
				return CSIComponentStatePlan{}, err
			}
			root = root || component.Identity.ExactKey() == deployment.Identity.ExactKey()
			key := strings.ToLower(component.Stem)
			owned[key] = true
			ownerKey := key + "\x00" + name
			if seenOwners[ownerKey] {
				continue
			}
			seenOwners[ownerKey] = true
			result.Owners = append(result.Owners, CSIComponentOwner{Stem: component.Stem, Name: "c!" + name})
		}
		if !root {
			return CSIComponentStatePlan{}, fmt.Errorf("CSI deployment %q is missing its root component", name)
		}
	}
	for stem := range selected {
		if !owned[stem] {
			return CSIComponentStatePlan{}, fmt.Errorf("CSI component %q has no deployment ownership", stem)
		}
	}
	sort.Slice(result.Components, func(i, j int) bool {
		return strings.ToLower(result.Components[i].Stem) < strings.ToLower(result.Components[j].Stem)
	})
	sort.Slice(result.Owners, func(i, j int) bool {
		a, b := result.Owners[i], result.Owners[j]
		if strings.EqualFold(a.Stem, b.Stem) {
			return a.Name < b.Name
		}
		return strings.ToLower(a.Stem) < strings.ToLower(b.Stem)
	})
	return result, nil
}

func validateCSIComponentStem(component PlannedComponent) error {
	parsed, err := parseComponentStem(component.Stem)
	if err != nil {
		return err
	}
	if strings.ContainsAny(component.Stem, `/\`) || !componentPathMayMatch(parsed, component.Identity) {
		return fmt.Errorf("CSI component stem does not match identity: %q", component.Stem)
	}
	hash, err := csiIdentityHash(component.Identity, false)
	if err != nil {
		return err
	}
	if !strings.EqualFold(parsed.Suffix, fmt.Sprintf("%016x", hash)) {
		return fmt.Errorf("CSI component identity hash mismatch: %q", component.Stem)
	}
	return nil
}
