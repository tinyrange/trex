package windows

import (
	"fmt"
	"strings"

	"go.starlark.net/starlark"
)

func registryIdentityKey(hive, key string) string {
	return strings.ToUpper(hive) + "\x00/" + strings.ToLower(strings.Trim(strings.ReplaceAll(key, "\\", "/"), "/"))
}

// Select only direct values or child names; nonmatching entries allocate no
// result objects. The script retains source-hive merging and tombstone policy.
func registryChildrenBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var entries *starlark.Dict
	var hive, key string
	values := false
	if err := starlark.UnpackArgs("registry_children", args, kwargs, "entries", &entries, "hive", &hive, "key", &key, "values?", &values); err != nil {
		return nil, err
	}
	base := registryIdentityKey(hive, key)
	prefix := strings.TrimRight(base, "/") + "/"
	if values {
		prefix = base + "\x00"
	}
	out := starlark.NewDict(0)
	for identity, value := range entries.Entries() {
		text, ok := starlark.AsString(identity)
		if !ok {
			return nil, fmt.Errorf("registry_children: identity must be a string")
		}
		if !strings.HasPrefix(text, prefix) {
			continue
		}
		name := text[len(prefix):]
		if values {
			if err := out.SetKey(starlark.String(name), value); err != nil {
				return nil, err
			}
		} else if name != "" {
			if slash := strings.IndexByte(name, '/'); slash >= 0 {
				name = name[:slash]
			}
			name = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(name, "%2f", "/"), "%2F", "/"), "%25", "%")
			if err := out.SetKey(starlark.String(strings.ToLower(name)), starlark.String(name)); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// Registry emulator identities encode HIVE, normalized key, and optionally
// value name with NUL separators. Partitioning keeps both dictionaries owned
// by the caller while sharing their unchanged values, just like dict copying.
func registryPartitionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var entries *starlark.Dict
	var hive, key string
	values := false
	if err := starlark.UnpackArgs("registry_partition", args, kwargs, "entries", &entries, "hive", &hive, "key", &key, "values?", &values); err != nil {
		return nil, err
	}
	base := registryIdentityKey(hive, key)
	base = strings.TrimRight(base, "/")
	exact := base
	if values {
		exact += "\x00"
	}
	descendant := base + "/"
	selected, remaining := starlark.NewDict(0), starlark.NewDict(entries.Len())
	for identity, value := range entries.Entries() {
		text, ok := starlark.AsString(identity)
		if !ok {
			return nil, fmt.Errorf("registry_partition: identity must be a string")
		}
		matches := text == exact
		if values {
			matches = strings.HasPrefix(text, exact)
		}
		target := remaining
		if matches || strings.HasPrefix(text, descendant) {
			target = selected
		}
		if err := target.SetKey(identity, value); err != nil {
			return nil, err
		}
	}
	return starlark.Tuple{selected, remaining}, nil
}
