package uup

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/tinyrange/trex/archive/wim"
)

// deploymentActivation is derived from canonical CSI deployment source records.
// A selected package may contain both active and merely staged deployments.
// Component inventory presence and package CurrentState do not distinguish them.
type deploymentActivation struct {
	deployments map[string]bool
	updates     map[string]bool
}

type cbsDeploymentSource struct {
	Package AssemblyIdentity
	Update  string
}

func parseCBSDeploymentSource(data []byte) (cbsDeploymentSource, error) {
	if len(data) < 8 || len(data) > 64<<10 {
		return cbsDeploymentSource{}, fmt.Errorf("invalid CBS deployment source framing")
	}
	length, extra := uint64(binary.LittleEndian.Uint32(data[:4])), uint64(binary.LittleEndian.Uint32(data[4:8]))
	if length+extra != uint64(len(data)-8) || !utf8.Valid(data[8:8+length]) {
		return cbsDeploymentSource{}, fmt.Errorf("invalid CBS deployment source framing")
	}
	text := string(data[8 : 8+length])
	if strings.ContainsAny(text, "\x00\r\n") {
		return cbsDeploymentSource{}, fmt.Errorf("invalid CBS deployment source text")
	}
	fields := strings.Split(text, "~")
	if len(fields) != 5 {
		return cbsDeploymentSource{}, fmt.Errorf("invalid CBS deployment source package")
	}
	version := strings.SplitN(fields[4], ".", 5)
	if len(version) != 5 || version[4] == "" {
		return cbsDeploymentSource{}, fmt.Errorf("CBS deployment source has no update name")
	}
	fields[4] = strings.Join(version[:4], ".")
	if _, ok := assemblyVersionParts(fields[4]); !ok {
		return cbsDeploymentSource{}, fmt.Errorf("invalid CBS deployment source version")
	}
	pack, err := ParsePackageManifestName(strings.Join(fields, "~") + ".mum")
	if err != nil {
		return cbsDeploymentSource{}, err
	}
	return cbsDeploymentSource{Package: pack, Update: version[4]}, nil
}

func loadDeploymentActivation(base *wim.Archive, imagePath string) (*deploymentActivation, error) {
	hive, err := openOfflineHive(base, strings.TrimSuffix(imagePath, "/")+"/Windows/System32/config/COMPONENTS", "COMPONENTS")
	if err != nil {
		return nil, err
	}
	root, err := hive.LookupParts([]string{"CanonicalData", "Deployments"})
	if err != nil {
		return nil, err
	}
	keys, err := hive.ReadSubkeys(root)
	if err != nil {
		return nil, err
	}
	result := &deploymentActivation{deployments: make(map[string]bool), updates: make(map[string]bool)}
	for _, key := range keys {
		cells, err := hive.ValueCells(key)
		if err != nil {
			return nil, err
		}
		var identity AssemblyIdentity
		sources := map[string]struct {
			value  string
			source cbsDeploymentSource
			flags  uint8
		}{}
		for _, cell := range cells {
			value, err := hive.ReadValue(cell)
			if err != nil {
				return nil, err
			}
			if strings.EqualFold(value.Name, "appid") {
				if value.Type != 3 {
					return nil, fmt.Errorf("deployment %q appid is not binary", key.Name)
				}
				identity, err = parseCSIIdentity(value.Data)
				if err != nil {
					return nil, fmt.Errorf("deployment %q: %w", key.Name, err)
				}
			}
			if len(value.Name) < 2 || (value.Name[:2] != "p!" && value.Name[:2] != "s!" && value.Name[:2] != "i!") {
				continue
			}
			if !strings.HasPrefix(value.Name[2:], "CBS_") || value.Type != 3 {
				return nil, fmt.Errorf("unsupported deployment source %q", value.Name)
			}
			source, err := parseCBSDeploymentSource(value.Data)
			if err != nil {
				return nil, fmt.Errorf("deployment %q source %q: %w", key.Name, value.Name, err)
			}
			length := binary.LittleEndian.Uint32(value.Data[:4])
			canonicalSource, err := cbsSourceKey(string(value.Data[8 : 8+length]))
			if err != nil || !strings.EqualFold(value.Name[2:], canonicalSource) {
				return nil, fmt.Errorf("deployment %q source %q key mismatch", key.Name, value.Name)
			}
			name := strings.ToLower(value.Name[2:])
			record := sources[name]
			if record.flags != 0 && record.value != string(value.Data) {
				return nil, fmt.Errorf("deployment %q source records disagree", key.Name)
			}
			record.value = string(value.Data)
			record.source = source
			switch value.Name[:2] {
			case "p!":
				record.flags |= 1
			case "s!":
				record.flags |= 2
			case "i!":
				record.flags |= 4
			}
			sources[name] = record
		}
		if identity.Name == "" {
			return nil, fmt.Errorf("deployment %q has no appid", key.Name)
		}
		canonicalKey, err := csiDeploymentKey(identity)
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(key.Name, canonicalKey) {
			return nil, fmt.Errorf("deployment %q identity hash mismatch", key.Name)
		}
		active := false
		for _, record := range sources {
			if record.flags&3 != 3 {
				return nil, fmt.Errorf("deployment %q lacks matching present/staged source records", key.Name)
			}
			installed := record.flags&4 != 0
			active = active || installed
			name := strings.ToLower(record.source.Update)
			result.updates[name] = result.updates[name] || installed
		}
		family := identity.StableKey()
		result.deployments[family] = result.deployments[family] || active
	}
	return result, nil
}

func (activation *deploymentActivation) rootActive(manifest *AssemblyManifest, reference AssemblyReference, identity AssemblyIdentity) (bool, error) {
	if activation == nil {
		return true, nil
	} // Legacy filename-only inventory has no activation source.
	if active, known := activation.deployments[identity.StableKey()]; known {
		return active, nil
	}
	// New deployments must use the package's explicit update conditions. Do not
	// infer enablement from component-store presence or a package-level state.
	var update *AssemblyPackageUpdate
	for i := range manifest.PackageUpdates {
		if manifest.PackageUpdates[i].Name == reference.UpdateName {
			if update != nil {
				return false, fmt.Errorf("duplicate package update %q", reference.UpdateName)
			}
			update = &manifest.PackageUpdates[i]
		}
	}
	if update == nil {
		return false, fmt.Errorf("component %q has no package update context", identity.Name)
	}
	active := true
	for _, condition := range update.Conditions {
		enabled, err := activation.evaluateCondition(condition)
		if err != nil {
			return false, fmt.Errorf("package %q update %q: %w", manifest.Identity.Name, update.Name, err)
		}
		active = active && enabled
	}
	return active, nil
}

func (activation *deploymentActivation) evaluateCondition(condition ManifestCondition) (bool, error) {
	if condition.Namespace != "" && condition.Namespace != "urn:schemas-microsoft-com:asm.v3" {
		return false, fmt.Errorf("unsupported update condition namespace %q", condition.Namespace)
	}
	switch condition.Name {
	case "applicable":
		for _, a := range condition.Attributes {
			if a.Namespace != "" || a.Name != "disposition" || a.Value != "detect" {
				return false, fmt.Errorf("unsupported applicable attribute %q=%q", a.Name, a.Value)
			}
		}
		if len(condition.Children) != 1 {
			return false, fmt.Errorf("applicable requires one condition")
		}
		return activation.evaluateCondition(condition.Children[0])
	case "detectUpdate":
		if len(condition.Attributes) != 0 || len(condition.Children) != 1 || condition.Children[0].Name != "parent" {
			return false, fmt.Errorf("unsupported detectUpdate shape")
		}
		parent := condition.Children[0]
		if (parent.Namespace != "" && parent.Namespace != "urn:schemas-microsoft-com:asm.v3") || len(parent.Children) != 0 || len(parent.Attributes) != 1 || parent.Attributes[0].Namespace != "" || parent.Attributes[0].Name != "name" {
			return false, fmt.Errorf("unsupported update parent predicate")
		}
		return activation.updates[strings.ToLower(parent.Attributes[0].Value)], nil
	case "selectable":
		if len(condition.Children) != 0 {
			return false, fmt.Errorf("unsupported selectable child condition")
		}
		enabled := false
		for _, a := range condition.Attributes {
			if a.Namespace != "" {
				return false, fmt.Errorf("unsupported selectable namespace")
			}
			switch a.Name {
			case "default":
				switch a.Value {
				case "true":
					enabled = true
				case "false":
					enabled = false
				default:
					return false, fmt.Errorf("unsupported selectable default %q", a.Value)
				}
			default:
				return false, fmt.Errorf("unsupported selectable attribute %q", a.Name)
			}
		}
		return enabled, nil
	default:
		return false, fmt.Errorf("unsupported update condition %q", condition.Name)
	}
}

func activeComponentClosure(roots map[string]struct{}, dependencies map[string][]string, applicable map[string]struct{}) map[string]struct{} {
	active := make(map[string]struct{})
	queue := make([]string, 0, len(roots))
	for key := range roots {
		queue = append(queue, key)
	}
	for len(queue) > 0 {
		key := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if _, ok := applicable[key]; !ok {
			continue
		}
		if _, seen := active[key]; seen {
			continue
		}
		active[key] = struct{}{}
		queue = append(queue, dependencies[key]...)
	}
	return active
}
