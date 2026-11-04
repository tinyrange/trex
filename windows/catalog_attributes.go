package windows

import (
	"fmt"
	"github.com/tinyrange/trex/windows/catalog"
	"go.starlark.net/starlark"
)

func catalogAttributesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("catalog_attributes", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(value, 64<<20)
	if err != nil {
		return nil, err
	}
	attrs, err := catalog.ParseAttributes(data)
	if err != nil {
		return nil, fmt.Errorf("catalog_attributes: %w", err)
	}
	return catalogAttributeValues(attrs)
}

func catalogAttributeValues(attrs []catalog.Attribute) (*starlark.List, error) {
	output := make([]starlark.Value, 0, len(attrs))
	for _, attr := range attrs {
		d := starlark.NewDict(6)
		for _, pair := range []starlark.Tuple{
			{starlark.String("oid"), starlark.String(attr.OID)},
			{starlark.String("critical"), starlark.Bool(attr.Critical)},
			{starlark.String("name_value"), starlark.Bool(attr.NameValue)},
			{starlark.String("name"), starlark.String(attr.Name)},
			{starlark.String("flags"), starlark.MakeUint64(uint64(attr.Flags))},
			{starlark.String("value"), starlark.Bytes(attr.Value)},
		} {
			if err := d.SetKey(pair[0], pair[1]); err != nil {
				return nil, err
			}
		}
		output = append(output, d)
	}
	return starlark.NewList(output), nil
}
