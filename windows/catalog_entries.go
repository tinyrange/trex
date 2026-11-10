package windows

import (
	"fmt"
	"github.com/tinyrange/trex/windows/catalog"
	"go.starlark.net/starlark"
	"strings"
)

func catalogEntriesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var nameValue starlark.Value = starlark.None
	if err := starlark.UnpackArgs("catalog_entries", args, kwargs, "file", &value, "name_value?", &nameValue); err != nil {
		return nil, err
	}
	filter := ""
	if nameValue != starlark.None {
		var ok bool
		filter, ok = starlark.AsString(nameValue)
		if !ok || filter == "" {
			return nil, fmt.Errorf("catalog_entries: name_value must be a nonempty string or None")
		}
		filter = strings.ToLower(filter)
	}
	data, err := bytesForBinaryValueLimited(value, 64<<20)
	if err != nil {
		return nil, err
	}
	var version int
	var entries []catalog.Entry
	if nameValue == starlark.None {
		version, entries, err = catalog.ParseEntries(data)
	} else {
		version, entries, err = catalog.ParseEntriesWithNameValue(data, filter)
	}
	if err != nil {
		return nil, fmt.Errorf("catalog_entries: %w", err)
	}
	values := make([]starlark.Value, 0, len(entries))
	for _, entry := range entries {
		attrs, err := catalogAttributeValues(entry.Attributes)
		if err != nil {
			return nil, err
		}
		d := starlark.NewDict(3)
		for _, pair := range []starlark.Tuple{
			{starlark.String("subject"), starlark.Bytes(entry.Subject)},
			{starlark.String("digest"), starlark.Bytes(entry.Digest)},
			{starlark.String("attributes"), attrs},
		} {
			if err := d.SetKey(pair[0], pair[1]); err != nil {
				return nil, err
			}
		}
		values = append(values, d)
	}
	result := starlark.NewDict(2)
	if err := result.SetKey(starlark.String("version"), starlark.MakeInt(version)); err != nil {
		return nil, err
	}
	if err := result.SetKey(starlark.String("entries"), starlark.NewList(values)); err != nil {
		return nil, err
	}
	return result, nil
}
