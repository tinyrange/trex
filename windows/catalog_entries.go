package windows

import (
	"fmt"
	"github.com/tinyrange/trex/windows/catalog"
	"go.starlark.net/starlark"
)

func catalogEntriesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("catalog_entries", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(value, 64<<20)
	if err != nil {
		return nil, err
	}
	version, entries, err := catalog.ParseEntries(data)
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
