package windows

import (
	"fmt"
	"strings"

	"go.starlark.net/starlark"
)

// Registry redirection tables are version-specific policy supplied by the
// caller. Only component-boundary matching and physical path construction
// belong here; no host or generic Windows-version defaults are consulted.
type registryPathMapper map[string]uint32

func registryPathMapperBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var rules *starlark.List
	if err := starlark.UnpackArgs("registry_path_mapper", args, kwargs, "rules", &rules); err != nil {
		return nil, err
	}
	if rules.Len() > 4096 {
		return nil, fmt.Errorf("registry path rule count exceeds bound")
	}
	mapper := registryPathMapper{}
	for value := range rules.Elements() {
		pair, ok := value.(starlark.Tuple)
		if !ok || len(pair) != 2 {
			return nil, fmt.Errorf("registry path rule must be (prefix, flags)")
		}
		prefix, ok := starlark.AsString(pair[0])
		if !ok || len(prefix) > 32768 || strings.ContainsRune(prefix, 0) || strings.Contains(prefix, `\\`) {
			return nil, fmt.Errorf("invalid registry path rule prefix")
		}
		folded := strings.ToLower(prefix)
		if !registryKeyWithin(folded, `\registry\machine`) || strings.HasSuffix(prefix, `\`) {
			return nil, fmt.Errorf("registry path rule requires canonical NT machine prefix")
		}
		var flags uint32
		if err := starlark.AsInt(pair[1], &flags); err != nil || flags & ^uint32(3) != 0 {
			return nil, fmt.Errorf("registry path rule flags must be 0..3")
		}
		// Last equal prefix wins, matching ordered native table selection.
		mapper[folded] = flags
	}
	return starlark.NewBuiltin("registry_path_mapper.resolve", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var key, architecture string
		if err := starlark.UnpackArgs("registry_path_mapper.resolve", args, kwargs, "key", &key, "architecture", &architecture); err != nil {
			return nil, err
		}
		scope, path, err := mapper.resolve(key, architecture)
		if err != nil {
			return nil, err
		}
		// Return a fresh mutable dictionary: callers cannot modify the mapper.
		result := starlark.NewDict(2)
		result.SetKey(starlark.String("scope"), starlark.String(scope))
		result.SetKey(starlark.String("path"), starlark.String(path))
		return result, nil
	}), nil
}

func (m registryPathMapper) resolve(key, architecture string) (string, string, error) {
	if strings.ContainsRune(key, 0) || strings.Contains(key, "$(") {
		return "", "", fmt.Errorf("registry pass requires a resolved key string")
	}
	key = strings.TrimRight(key, `\`)
	parts := strings.Split(key, `\`)
	for _, part := range parts {
		if part == "" {
			return "", "", fmt.Errorf("registry pass requires nonempty ordinary key components")
		}
	}
	if architecture != "amd64" && architecture != "x86" && architecture != "wow64" {
		return "", "", fmt.Errorf("unsupported registry architecture")
	}
	var root string
	switch strings.ToLower(parts[0]) {
	case "hkey_local_machine", "hklm":
		root = `\Registry\Machine`
	case "hkey_classes_root", "hkcr":
		root = `\Registry\Machine\SOFTWARE\Classes`
	default:
		for _, part := range parts[1:] {
			if strings.ToLower(part) == "wow6432node" {
				return "", "", fmt.Errorf("explicit user WOW node requires separate policy")
			}
		}
		switch strings.ToLower(parts[0]) {
		case "hkey_current_user":
			path := `\Registry\User`
			if len(parts) > 1 {
				path += `\` + strings.Join(parts[1:], `\`)
			}
			return "user", path, nil
		case "hkey_users":
			if len(parts) > 1 && strings.ToLower(parts[1]) == ".default" {
				return "system", `\Registry\User\` + strings.Join(parts[1:], `\`), nil
			}
		}
		return "", "", fmt.Errorf("unsupported registry declaration root")
	}
	path := root
	if len(parts) > 1 {
		path += `\` + strings.Join(parts[1:], `\`)
	}
	if architecture == "amd64" {
		return "system", path, nil
	}
	original := path
	parts = strings.Split(path, `\`)
	explicit := -1
	for i, part := range parts {
		if strings.ToLower(part) == "wow6432node" {
			if explicit != -1 || len(parts) <= 3 || strings.ToLower(parts[3]) != "software" || !(i == 4 || i == 5 && strings.ToLower(parts[4]) == "classes") {
				return "", "", fmt.Errorf("unsupported explicit WOW6432Node placement")
			}
			explicit = i
		}
	}
	if explicit >= 0 {
		parts = append(parts[:explicit], parts[explicit+1:]...)
		path = strings.Join(parts, `\`)
	}
	folded := strings.ToLower(path)
	match, anchor := -1, ""
	for candidate := folded; candidate != ""; {
		if flags, ok := m[candidate]; ok {
			if match == -1 {
				match = int(flags)
			}
			if flags&2 != 0 && anchor == "" {
				anchor = candidate
			}
		}
		at := strings.LastIndexByte(candidate, '\\')
		if at < 0 {
			break
		}
		candidate = candidate[:at]
	}
	if match&1 != 0 && match != -1 {
		if anchor == "" {
			return "", "", fmt.Errorf("missing registry redirection insertion point")
		}
		// Locate the original component boundary, not a byte offset into the
		// lowercased path: Unicode case mapping may change UTF-8 byte lengths.
		count := strings.Count(anchor, `\`)
		end := 0
		for i := 0; i < count; i++ {
			at := strings.IndexByte(path[end:], '\\')
			end += at + 1
		}
		if at := strings.IndexByte(path[end:], '\\'); at >= 0 {
			end += at
		} else {
			end = len(path)
		}
		path = path[:end] + `\WOW6432Node` + path[end:]
	}
	if strings.ToLower(path) == strings.ToLower(original) {
		path = original
	}
	return "system", path, nil
}
