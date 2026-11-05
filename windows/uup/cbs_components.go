package uup

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// CBSComponentInventoryEntry is one exact CSI identity and its effective
// analyzer owner elevations. These are not package CurrentState values. Purely
// staged owners are excluded; a caller must resolve transaction overlays first.
// Identity is the canonical UTF-8 COMPONENTS identity value. Empty Owners means
// a known version with no effective installed owners, not an active component.
type CBSComponentInventoryEntry struct {
	Identity []byte
	Owners   []uint32
}

type cbsComponentVersion struct {
	version [4]uint64
	owners  []uint32
}

// CBSComponentStateIndex is an immutable component-analyzer snapshot. It does
// not infer installed ownership from manifest presence or choose CSI winners.
type CBSComponentStateIndex struct {
	families map[string][]cbsComponentVersion
}

func cbsComponentFamily(id AssemblyIdentity) (string, error) {
	version, err := cbsParentVersion(id)
	if err != nil {
		return "", err
	}
	// GetKeyFormFromDefinitionIdentityLessVersion removes the entire version
	// only for nonSxS. Side-by-side identities retain their major/minor family;
	// an active owner in another major/minor must not activate this branch.
	id.Version = fmt.Sprintf("%d.%d.0.0", version[0], version[1])
	if strings.EqualFold(id.VersionScope, "nonSxS") {
		id.Version = "0.0.0.0"
	}
	text, err := marshalCSIIdentity(id)
	return strings.ToLower(string(text)), err
}

func NewCBSComponentStateIndex(entries []CBSComponentInventoryEntry) (*CBSComponentStateIndex, error) {
	if len(entries) > 1<<20 {
		return nil, fmt.Errorf("CBS component inventory exceeds bound")
	}
	result := &CBSComponentStateIndex{families: map[string][]cbsComponentVersion{}}
	seen := map[string]bool{}
	totalOwners, totalBytes := 0, 0
	for _, e := range entries {
		totalOwners += len(e.Owners)
		totalBytes += len(e.Identity)
		if totalOwners > 1<<20 || totalBytes > 64<<20 {
			return nil, fmt.Errorf("CBS component inventory data exceeds bound")
		}
		id, err := parseCSIIdentity(e.Identity)
		if err != nil {
			return nil, err
		}
		v, err := cbsParentVersion(id)
		if err != nil {
			return nil, err
		}
		family, err := cbsComponentFamily(id)
		if err != nil {
			return nil, err
		}
		key := fmt.Sprintf("%s/%v", family, v)
		if seen[key] {
			return nil, fmt.Errorf("duplicate CBS component inventory identity %q", id.Name)
		}
		seen[key] = true
		owners := append([]uint32(nil), e.Owners...)
		for _, owner := range owners {
			switch owner &^ 1 {
			case 2, 4, 8, 32, 128:
			default:
				return nil, fmt.Errorf("unsupported CBS component owner elevation %#x", owner)
			}
		}
		result.families[family] = append(result.families[family], cbsComponentVersion{v, owners})
	}
	for key, versions := range result.families {
		sort.Slice(versions, func(i, j int) bool { return compareCBSComponentVersion(versions[i].version, versions[j].version) < 0 })
		result.families[key] = versions
	}
	return result, nil
}

func compareCBSComponentVersion(a, b [4]uint64) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// SelfUpdate implements CheckInternalDetectComponentApplicability for one
// identity target. Only strictly lower versions participate; an already staged
// or installed copy of the target is not its own applicability evidence. An
// install elevation is unconditional. Other elevations require an active
// predecessor owner and obey the latest lower version/build branch boundaries.
// Multiple assemblyIdentity targets in updateComponent are alternatives.
func (index *CBSComponentStateIndex) SelfUpdate(id AssemblyIdentity, elevation string) (bool, error) {
	if index == nil {
		return false, fmt.Errorf("CBS updateComponent requires an explicit component snapshot")
	}
	request, ok := map[string]uint32{"revision": 2, "distribution": 4, "build": 8, "version": 32, "install": 128}[elevation]
	if !ok {
		return false, fmt.Errorf("unsupported CBS component elevation %q", elevation)
	}
	target, err := cbsParentVersion(id)
	if err != nil {
		return false, err
	}
	family, err := cbsComponentFamily(id)
	if err != nil {
		return false, err
	}
	var versionBranch, buildBranch [4]uint64
	active := false
	for _, v := range index.families[family] {
		if compareCBSComponentVersion(v.version, target) >= 0 {
			break
		}
		for _, owner := range v.owners {
			ceiling := owner
			if owner&1 != 0 || owner == 128 {
				active = true
				ceiling = 128
			}
			if ceiling >= 32 {
				versionBranch = v.version
			}
			if ceiling >= 8 {
				buildBranch = v.version
			}
		}
	}
	if request == 128 {
		return true, nil
	}
	if !active {
		return false, nil
	}
	majorMinor := target[0]<<16 | target[1]
	previousMajorMinor := versionBranch[0]<<16 | versionBranch[1]
	if request >= 32 {
		return majorMinor >= previousMajorMinor, nil
	}
	if majorMinor != previousMajorMinor {
		return false, nil
	}
	if request >= 8 {
		return target[2] >= buildBranch[2], nil
	}
	// Native distribution accessor returns zero, not a slice of the revision.
	// Revision/distribution therefore require the same version and build branch.
	return target[2] == buildBranch[2], nil
}

// WithComponentState replaces the analyzer snapshot and invalidates derived
// update applicability, while retaining explicit published session targets.
// No ownership is inferred and the old update snapshot remains unchanged.
func (index *CBSUpdateStateIndex) WithComponentState(components *CBSComponentStateIndex) (*CBSUpdateStateIndex, error) {
	if components == nil {
		return nil, fmt.Errorf("nil CBS component snapshot")
	}
	next, err := index.WithIntendedStates(nil)
	if err != nil {
		return nil, err
	}
	next.graph.components = components
	return next, nil
}

func (g *cbsUpdateIntents) componentPredicate(d ManifestCondition) (cbsUpdateDetection, error) {
	attrs, err := cbsConditionAttributes(d, "elevate")
	if err != nil {
		return cbsUpdateDetection{}, err
	}
	if len(d.Children) == 0 {
		return cbsUpdateDetection{}, fmt.Errorf("CBS updateComponent has no targets")
	}
	result := cbsUpdateDetection{state: 0}
	for _, a := range d.Children {
		if a.Name != "assemblyIdentity" || len(a.Children) != 0 {
			return result, fmt.Errorf("invalid CBS updateComponent target")
		}
		if _, err := cbsConditionAttributes(a, "name", "version", "processorArchitecture", "language", "publicKeyToken", "buildType", "versionScope", "type"); err != nil {
			return result, err
		}
		start := xml.StartElement{}
		for _, attr := range a.Attributes {
			if attr.Namespace == "" && attr.Name != "xmlns" {
				start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: attr.Name}, Value: attr.Value})
			}
		}
		id, err := parseAssemblyIdentity(start)
		if err != nil {
			return result, err
		}
		match, err := g.components.SelfUpdate(id, attrs["elevate"])
		if err != nil {
			return result, err
		}
		result.match = result.match || match
	}
	return result, nil
}
