package ibmisave

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Builtin exposes stored sections without pretending they are restored objects.
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	maximum := 100000
	if err := starlark.UnpackArgs("ibmi_save", args, kwargs, "file", &file, "maximum_entries?", &maximum); err != nil {
		return nil, err
	}
	a, err := Open(file, maximum)
	if err != nil {
		return nil, err
	}
	objects := make([]starlark.Value, len(a.Objects))
	for i, o := range a.Objects {
		sections := make([]starlark.Value, len(o.Sections))
		for j, s := range o.Sections {
			sections[j] = starfile.NewRecord(starlark.StringDict{"data": s.Data, "stored_size": starlark.MakeInt64(s.Data.Size()), "logical_size": starlark.MakeUint(uint(s.LogicalSize)), "address": starlark.MakeUint64(s.Address)})
		}
		objects[i] = starfile.NewRecord(starlark.StringDict{"name": starlark.String(o.Name), "raw_name": starlark.Bytes(o.RawName), "group": starlark.MakeInt(o.Group), "offset": starlark.MakeInt64(o.Offset), "object_type": starlark.MakeUint(uint(o.Type)), "release": starlark.String(fmt.Sprintf("%04x", o.Release)), "target_release": starlark.String(fmt.Sprintf("%04x", o.TargetRelease)), "declared_data_blocks": starlark.MakeUint(uint(o.DeclaredDataBlocks)), "header": o.Header, "stored_data": o.Data, "trailer": o.Trailer, "sections": starlark.NewList(sections)})
	}
	padding := make([]starlark.Value, len(a.Padding))
	for i, p := range a.Padding {
		padding[i] = p
	}
	return starfile.NewRecord(starlark.StringDict{"objects": starlark.NewList(objects), "groups": starlark.MakeInt(a.Groups), "padding": starlark.NewList(padding)}), nil
}
