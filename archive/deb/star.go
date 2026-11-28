package deb

import (
	"fmt"
	"maps"
	"slices"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func ControlBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := int64(64 << 20)
	if err := starlark.UnpackArgs("debian_control", args, kwargs, "file", &value, "maximum_bytes?", &maximum); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok || maximum <= 0 || maximum > 256<<20 {
		return nil, fmt.Errorf("debian_control: expected file and a limit of 1..256 MiB")
	}
	paragraphs, err := ReadControl(source, maximum)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, 0, len(paragraphs))
	for _, paragraph := range paragraphs {
		fields := starlark.NewDict(len(paragraph.Fields))
		for _, name := range slices.Sorted(maps.Keys(paragraph.Fields)) {
			if err := fields.SetKey(starlark.String(name), starlark.String(paragraph.Fields[name])); err != nil {
				return nil, err
			}
		}
		values = append(values, starfile.NewRecord(starlark.StringDict{
			"fields": fields,
			"raw":    starlark.String(paragraph.Raw),
		}))
	}
	return starlark.NewList(values), nil
}
