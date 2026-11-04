package windows

import (
	"fmt"
	"github.com/tinyrange/trex/windows/cdf"
	"go.starlark.net/starlark"
)

func cdfFileMapBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if e := starlark.UnpackArgs("cdf_filemap", args, kwargs, "data", &value); e != nil {
		return nil, e
	}
	b, ok := value.(starlark.Bytes)
	if !ok {
		return nil, fmt.Errorf("cdf_filemap requires bytes")
	}
	if len(b) > cdf.MaxSize {
		return nil, fmt.Errorf("CDF input exceeds 64 MiB")
	}
	d, e := cdf.Parse([]byte(b))
	if e != nil {
		return nil, e
	}
	m, e := d.FileMap()
	if e != nil {
		return nil, e
	}
	return cdfFileMapToDict(m), nil
}

func cdfFileMapToDict(m *cdf.FileMap) *starlark.Dict {
	out := starlark.NewDict(4)
	_ = out.SetKey(starlark.String("path"), starlark.String(m.Path))
	_ = out.SetKey(starlark.String("root_selector"), starlark.MakeUint64(uint64(m.RootSelector)))
	identities := make([]starlark.Value, len(m.Identities))
	for i, identity := range m.Identities {
		attrs := make([]starlark.Value, len(identity))
		for j, a := range identity {
			attrs[j] = starlark.Tuple{starlark.String(a.Namespace), starlark.String(a.Name), starlark.String(a.Value)}
		}
		identities[i] = starlark.NewList(attrs)
	}
	_ = out.SetKey(starlark.String("identities"), starlark.NewList(identities))
	entries := make([]starlark.Value, len(m.Entries))
	for i, f := range m.Entries {
		item := starlark.NewDict(4)
		_ = item.SetKey(starlark.String("name"), starlark.String(f.Name))
		_ = item.SetKey(starlark.String("display_name"), starlark.String(f.DisplayName))
		_ = item.SetKey(starlark.String("flags"), starlark.MakeUint64(uint64(f.Flags)))
		_ = item.SetKey(starlark.String("identity"), starlark.MakeUint64(uint64(f.Identity)))
		entries[i] = item
	}
	_ = out.SetKey(starlark.String("entries"), starlark.NewList(entries))
	return out
}
