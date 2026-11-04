package windows

import (
	"fmt"
	"github.com/tinyrange/trex/windows/cdf"
	"go.starlark.net/starlark"
)

func cdfFileMapEncodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var doc *starlark.Dict
	if e := starlark.UnpackArgs("cdf_filemap_encode", args, kwargs, "document", &doc); e != nil {
		return nil, e
	}
	m, e := cdfFileMapFromDict(doc)
	if e != nil {
		return nil, e
	}
	out, e := m.Marshal()
	if e != nil {
		return nil, e
	}
	return starlark.Bytes(out), nil
}

func cdfFileMapFromDict(doc *starlark.Dict) (*cdf.FileMap, error) {
	m := &cdf.FileMap{}
	var root starlark.Int
	var ids, entries *starlark.List
	if e := starlark.UnpackArgs("FileMap", nil, doc.Items(), "path", &m.Path, "root_selector", &root, "identities", &ids, "entries", &entries); e != nil {
		return nil, e
	}
	r, ok := root.Uint64()
	if !ok || r > 2 {
		return nil, fmt.Errorf("FileMap: invalid root selector")
	}
	m.RootSelector = uint32(r)
	if ids.Len() > 1<<20 || entries.Len() > 1<<20 {
		return nil, fmt.Errorf("FileMap: too many records")
	}
	m.Identities = make([][]cdf.IdentityAttribute, ids.Len())
	total := 0
	for i := 0; i < ids.Len(); i++ {
		attrs, ok := ids.Index(i).(*starlark.List)
		if !ok || attrs.Len() > 1024 {
			return nil, fmt.Errorf("FileMap: invalid attribute list")
		}
		if attrs.Len() > (1<<20)-total {
			return nil, fmt.Errorf("FileMap: attribute count limit")
		}
		total += attrs.Len()
		m.Identities[i] = make([]cdf.IdentityAttribute, attrs.Len())
		for j := 0; j < attrs.Len(); j++ {
			a, ok := attrs.Index(j).(starlark.Tuple)
			if !ok || len(a) != 3 {
				return nil, fmt.Errorf("FileMap: attribute must be namespace/name/value tuple")
			}
			fields := []*string{&m.Identities[i][j].Namespace, &m.Identities[i][j].Name, &m.Identities[i][j].Value}
			for k, target := range fields {
				s, ok := starlark.AsString(a[k])
				if !ok {
					return nil, fmt.Errorf("FileMap: attribute fields must be strings")
				}
				*target = s
			}
		}
	}
	m.Entries = make([]cdf.FileMapEntry, entries.Len())
	for i := 0; i < entries.Len(); i++ {
		f, ok := entries.Index(i).(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("FileMap: entry must be dict")
		}
		var flags, identity starlark.Int
		if e := starlark.UnpackArgs("FileMap entry", nil, f.Items(), "name", &m.Entries[i].Name, "display_name", &m.Entries[i].DisplayName, "flags", &flags, "identity", &identity); e != nil {
			return nil, e
		}
		fv, ok := flags.Uint64()
		if !ok || fv > 0xffffffff {
			return nil, fmt.Errorf("FileMap: flags outside uint32")
		}
		iv, ok := identity.Uint64()
		if !ok || iv > 0xffffffff {
			return nil, fmt.Errorf("FileMap: identity outside uint32")
		}
		m.Entries[i].Flags = uint32(fv)
		m.Entries[i].Identity = uint32(iv)
	}
	return m, nil
}
