package windows

import (
	"fmt"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// importRegistryHive avoids exporting every value and key to intermediate
// Starlark dictionaries just to import them again. Policy additions still use
// the same hive_from_patches implementation after this lossless source pass.
func importRegistryHive(root *registryTree, source starlark.Value, sourceDrive, targetDrive string, excludedKeys, excludedValues starlark.Value) error {
	file, ok := source.(starfile.File)
	if !ok {
		return fmt.Errorf("hive_from_patches: source is %s, want file", source.Type())
	}
	validDrive := func(s string) bool {
		return len(s) == 2 && s[1] == ':' && (s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z')
	}
	if sourceDrive != "" || targetDrive != "" {
		if !validDrive(sourceDrive) || !validDrive(targetDrive) {
			return fmt.Errorf("hive_from_patches: source_drive and target_drive must both be ASCII drive letters with colons")
		}
	}
	sourceDrive, targetDrive = strings.ToUpper(sourceDrive), strings.ToUpper(targetDrive)
	relocate := sourceDrive != targetDrive
	text := func(s string) string {
		if !relocate || !strings.Contains(s, ":") {
			return s
		}
		return relocateDriveText(s, sourceDrive[0], targetDrive[0])
	}
	// Policy paths normalize separators; literal key components stay intact.
	normalize := func(s string) string {
		return "/" + strings.ToLower(strings.Trim(strings.ReplaceAll(s, "\\", "/"), "/"))
	}
	removed := make(map[string]bool)
	if excludedKeys != starlark.None {
		list, ok := excludedKeys.(*starlark.List)
		if !ok {
			return fmt.Errorf("hive_from_patches: exclude_keys must be a list")
		}
		for i := 0; i < list.Len(); i++ {
			s, ok := starlark.AsString(list.Index(i))
			if !ok {
				return fmt.Errorf("hive_from_patches: exclude_keys[%d] must be a string", i)
			}
			removed[normalize(s)] = true
		}
	}
	type valueID struct{ key, name string }
	removedValues := make(map[valueID]bool)
	if excludedValues != starlark.None {
		list, ok := excludedValues.(*starlark.List)
		if !ok {
			return fmt.Errorf("hive_from_patches: exclude_values must be a list")
		}
		for i := 0; i < list.Len(); i++ {
			item, ok := list.Index(i).(*starlark.Dict)
			if !ok {
				return fmt.Errorf("hive_from_patches: exclude_values[%d] must be a dict", i)
			}
			key, err := requiredPatchString(item, "key")
			if err != nil {
				return err
			}
			name, err := requiredPatchString(item, "name")
			if err != nil {
				return err
			}
			removedValues[valueID{normalize(key), strings.ToLower(name)}] = true
		}
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return err
	}
	hive, err := newRegistryHive(&starfile.Bytes{Name: file.String(), Data: data})
	if err != nil {
		return err
	}
	first, err := hive.readKey(hive.rootCell)
	if err != nil {
		return err
	}
	seen := make(hiveTraversal)
	var visit func(hiveKey, []string) error
	visit = func(key hiveKey, parts []string) error {
		if err := seen.enter(key, len(parts)); err != nil {
			return err
		}
		normalized := normalize(registryDisplayPath(parts))
		skip := false
		for candidate := normalized; candidate != ""; {
			if removed[candidate] {
				skip = true
				break
			}
			i := strings.LastIndexByte(candidate, '/')
			if i < 0 {
				break
			}
			candidate = candidate[:i]
		}
		if !skip {
			node := ensureRegistryKeyParts(root, parts)
			node.flags, node.flagsSet = key.flags, true
			node.class, err = hive.readKeyClass(key)
			if err != nil {
				return err
			}
			node.security, err = hive.readKeySecurity(key)
			if err != nil {
				return err
			}
			if err := validateSelfRelativeSecurityDescriptor(node.security); err != nil {
				return err
			}
			values, err := hive.readRawValues(key)
			if err != nil {
				return err
			}
			for _, value := range values {
				name := text(value.name)
				if removedValues[valueID{normalized, strings.ToLower(name)}] {
					continue
				}
				raw := value.value
				if relocate && (raw.typ == regSZ || raw.typ == regExpandSZ || raw.typ == regMultiSZ) {
					raw.data = relocateDriveUTF16(raw.data, sourceDrive[0], targetDrive[0])
				}
				// The current node is already resolved. Rewalking all ancestors
				// for every imported value makes deep hives needlessly expensive.
				setRegistryValueParts(node, nil, name, raw)
			}
		}
		children, err := hive.readSubkeys(key)
		if err != nil {
			return err
		}
		for _, child := range children {
			if err := visit(child, appendRegistryPathPart(parts, text(child.name))); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(first, nil)
}
