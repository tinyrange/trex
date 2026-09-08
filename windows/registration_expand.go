package windows

import (
	"fmt"
	"strings"

	"go.starlark.net/starlark"
)

// Preserve registration-resource substitution order, including substitutions
// introduced by earlier entries and the historical four-pass bound.
func registrationExpandBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var replacements *starlark.Dict
	if err := starlark.UnpackArgs("registration_expand", args, kwargs, "value", &value, "replacements", &replacements); err != nil {
		return nil, err
	}
	output, ok := starlark.AsString(value)
	if !ok {
		return value, nil
	}
	type replacement struct{ upper, lower, value string }
	entries := make([]replacement, 0, replacements.Len())
	for key, v := range replacements.Entries() {
		name, ok := starlark.AsString(key)
		if !ok {
			return nil, fmt.Errorf("registration_expand: names must be strings")
		}
		text, ok := starlark.AsString(v)
		if !ok {
			return nil, fmt.Errorf("registration_expand: replacements must be strings")
		}
		entries = append(entries, replacement{"%" + strings.ToUpper(name) + "%", "%" + strings.ToLower(name) + "%", text})
	}
	for pass := 0; pass < 4; pass++ {
		previous := output
		for _, entry := range entries {
			output = strings.ReplaceAll(output, entry.upper, entry.value)
			output = strings.ReplaceAll(output, entry.lower, entry.value)
		}
		if output == previous {
			break
		}
	}
	return starlark.String(output), nil
}
