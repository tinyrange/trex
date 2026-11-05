package uup

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/tinyrange/trex/archive/wim"
)

// parseCSIIdentity reads the UTF-8 identity value in COMPONENTS, not the lossy
// display name encoded in the registry key/WinSxS path. Unknown or repeated
// attributes are rejected rather than silently weakening identity matching.
func parseCSIIdentity(data []byte) (AssemblyIdentity, error) {
	if len(data) == 0 || len(data) > 64<<10 || !utf8.Valid(data) || strings.ContainsAny(string(data), "\x00\r\n") {
		return AssemblyIdentity{}, fmt.Errorf("invalid CSI identity encoding or size")
	}
	fields := strings.Split(string(data), ", ")
	id := AssemblyIdentity{Name: fields[0]}
	if id.Name == "" || strings.ContainsAny(id.Name, ",=\"") {
		return AssemblyIdentity{}, fmt.Errorf("invalid CSI identity name")
	}
	seen := map[string]bool{}
	for _, field := range fields[1:] {
		key, value, ok := strings.Cut(field, "=")
		key = strings.ToLower(key)
		if !ok || value == "" || strings.ContainsAny(value, ",=\"") || seen[key] {
			return AssemblyIdentity{}, fmt.Errorf("invalid or duplicate CSI identity attribute %q", field)
		}
		seen[key] = true
		switch key {
		case "culture":
			id.Language = value
		case "version":
			id.Version = value
		case "publickeytoken":
			id.PublicKeyToken = value
		case "processorarchitecture":
			id.ProcessorArchitecture = value
		case "versionscope":
			id.VersionScope = value
		case "type":
			id.Attributes = append(id.Attributes, ManifestAttribute{Name: "type", Value: value})
		default:
			return AssemblyIdentity{}, fmt.Errorf("unsupported CSI identity attribute %q", key)
		}
	}
	for _, key := range []string{"culture", "version", "publickeytoken", "processorarchitecture"} {
		if !seen[key] {
			return AssemblyIdentity{}, fmt.Errorf("CSI identity missing %s", key)
		}
	}
	if _, ok := assemblyVersionParts(id.Version); !ok {
		return AssemblyIdentity{}, fmt.Errorf("invalid CSI identity version %q", id.Version)
	}
	return id, nil
}

func installedComponentIdentities(base *wim.Archive, imagePath string) ([]manifestPath, error) {
	hive, err := openOfflineHive(base, strings.TrimSuffix(imagePath, "/")+"/Windows/System32/config/COMPONENTS", "COMPONENTS")
	if err != nil {
		return nil, err
	}
	values, err := hive.SubkeyValues(cbsComponentsKey, "identity")
	if err != nil {
		return nil, fmt.Errorf("enumerate CBS component identities: %w", err)
	}
	result := make([]manifestPath, 0, len(values))
	for _, value := range values {
		name := value.Key + ".manifest"
		component, err := ParseComponentManifestName(name)
		if err != nil {
			// Non-component housekeeping keys are not inventory.
			continue
		}
		if !value.Found || value.Value.Type != 3 {
			return nil, fmt.Errorf("CBS component %q has no binary identity", value.Key)
		}
		id, err := parseCSIIdentity(value.Value.Data)
		if err != nil {
			return nil, fmt.Errorf("CBS component %q: %w", value.Key, err)
		}
		if !componentPathMayMatch(component, id) {
			return nil, fmt.Errorf("CBS component %q does not match its full identity", value.Key)
		}
		hash, err := csiIdentityHash(id, false)
		if err != nil {
			return nil, fmt.Errorf("CBS component %q: %w", value.Key, err)
		}
		if !strings.EqualFold(component.Suffix, fmt.Sprintf("%016x", hash)) {
			return nil, fmt.Errorf("CBS component %q identity hash mismatch", value.Key)
		}
		result = append(result, manifestPath{Path: name, Identity: id, Component: component})
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("COMPONENTS hive contains no component identities")
	}
	return result, nil
}

func newExactAssemblyImageState(packageNames []string, components []manifestPath) (*assemblyImageState, error) {
	state, err := newAssemblyImageState(packageNames, nil)
	if err != nil {
		return nil, err
	}
	state.exactComponentInventory = true
	state.exactComponents = make(map[string]manifestPath)
	state.latestExactComponentByStable = make(map[string]manifestPath)
	seen := make(map[string]string)
	for _, component := range components {
		exact := component.Identity.ExactKey()
		if prior, ok := seen[exact]; ok && !strings.EqualFold(prior, component.Component.Stem) {
			return nil, fmt.Errorf("duplicate full component identity %q in %q and %q", component.Identity.Name, prior, component.Component.Stem)
		}
		seen[exact] = component.Component.Stem
		state.rememberExactComponent(component)
	}
	return state, nil
}

func (state *assemblyImageState) rememberExactComponent(component manifestPath) {
	state.exactComponents[component.Identity.ExactKey()] = component
	state.installedComponentExact[component.Identity.ExactKey()] = struct{}{}
	state.componentCandidates = append(state.componentCandidates, component)
	key := component.Identity.StableKey()
	if previous, ok := state.latestExactComponentByStable[key]; !ok || compareVersions(component.Identity.Version, previous.Identity.Version) > 0 {
		state.latestExactComponentByStable[key] = component
	}
}
