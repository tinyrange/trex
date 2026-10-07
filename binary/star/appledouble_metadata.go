package star

import (
	"fmt"
	"github.com/tinyrange/trex/binary/appledouble"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func appleDoubleMetadataBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	if err := starlark.UnpackArgs("appledouble_metadata", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	m, err := appledouble.OpenMetadata(file)
	if err != nil {
		return nil, err
	}
	out := starlark.NewDict(4)
	var finder, resource starlark.Value = starlark.None, starlark.None
	if m.FinderInfo != nil {
		finder = starfile.NewReader("FinderInfo", m.FinderInfo)
	}
	if m.Resource != nil {
		resource = starfile.NewReader("resource fork", m.Resource)
	}
	attrs := starlark.NewDict(len(m.Attributes))
	for name, data := range m.Attributes {
		attrs.SetKey(starlark.String(name), starfile.NewReader(fmt.Sprintf("attribute %s", name), data))
	}
	other := starlark.NewDict(len(m.Other))
	for _, e := range m.Other {
		other.SetKey(starlark.MakeUint(uint(e.ID)), starfile.NewReader("AppleDouble entry", e.Data))
	}
	out.SetKey(starlark.String("finder_info"), finder)
	out.SetKey(starlark.String("resource"), resource)
	out.SetKey(starlark.String("xattrs"), attrs)
	out.SetKey(starlark.String("other"), other)
	return out, nil
}
