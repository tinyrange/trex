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
	// Exclusions are a component trie: display paths are ambiguous when an
	// actual key name contains a slash. Legacy strings still accept either
	// separator, while key_parts records preserve every component literally.
	type exclusion struct {
		children map[string]*exclusion
		remove   bool
		values   map[string]bool
	}
	policy := &exclusion{}
	legacyParts := func(s string) []string {
		s = strings.Trim(strings.ReplaceAll(s, "\\", "/"), "/")
		if s == "" {
			return nil
		}
		return strings.Split(s, "/")
	}
	parseParts := func(value starlark.Value) ([]string, error) {
		if s, ok := starlark.AsString(value); ok {
			return legacyParts(s), nil
		}
		item, ok := value.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("want string or key/key_parts dict, got %s", value.Type())
		}
		if _, found, err := item.Get(starlark.String("key_parts")); err != nil {
			return nil, err
		} else if found {
			parts, _, err := registryPathFromDict(item)
			return parts, err
		}
		s, err := requiredPatchString(item, "key")
		return legacyParts(s), err
	}
	selectPolicy := func(parts []string) *exclusion {
		node := policy
		for _, part := range parts {
			if node.children == nil {
				node.children = make(map[string]*exclusion)
			}
			folded := strings.ToLower(part)
			if node.children[folded] == nil {
				node.children[folded] = &exclusion{}
			}
			node = node.children[folded]
		}
		return node
	}
	if excludedKeys != starlark.None {
		list, ok := excludedKeys.(*starlark.List)
		if !ok {
			return fmt.Errorf("hive_from_patches: exclude_keys must be a list")
		}
		for i := 0; i < list.Len(); i++ {
			parts, err := parseParts(list.Index(i))
			if err != nil {
				return fmt.Errorf("hive_from_patches: exclude_keys[%d]: %w", i, err)
			}
			selectPolicy(parts).remove = true
		}
	}
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
			parts, err := parseParts(item)
			if err != nil {
				return fmt.Errorf("hive_from_patches: exclude_values[%d]: %w", i, err)
			}
			name, err := requiredPatchString(item, "name")
			if err != nil {
				return err
			}
			node := selectPolicy(parts)
			if node.values == nil {
				node.values = make(map[string]bool)
			}
			node.values[strings.ToLower(name)] = true
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
	var visit func(hiveKey, []string, *exclusion, bool) error
	visit = func(key hiveKey, parts []string, selected *exclusion, skip bool) error {
		if err := seen.enter(key, len(parts)); err != nil {
			return err
		}
		skip = skip || selected != nil && selected.remove
		if !skip {
			node := ensureRegistryKeyParts(root, parts)
			node.flags, node.flagsSet = key.flags, true
			node.nameFlags = key.nameFlags
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
				if selected != nil && selected.values[strings.ToLower(name)] {
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
			name := text(child.name)
			var childPolicy *exclusion
			if selected != nil {
				childPolicy = selected.children[strings.ToLower(name)]
			}
			if err := visit(child, appendRegistryPathPart(parts, name), childPolicy, skip); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(first, nil, policy, false)
}
