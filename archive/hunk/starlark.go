package hunk

import (
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func fileValue(f starfile.File) starlark.Value {
	if f == nil {
		return starlark.None
	}
	return f
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return builtin(args, kwargs, false)
}

func BuiltinLoad(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return builtin(args, kwargs, true)
}

func builtin(args starlark.Tuple, kwargs []starlark.Tuple, load bool) (starlark.Value, error) {
	var value starlark.Value
	maximum := 1000000
	if err := starlark.UnpackArgs("hunk_objects", args, kwargs, "file", &value, "maximum_records?", &maximum); err != nil {
		return nil, err
	}
	f, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("hunk_objects: expected file")
	}
	open := OpenObjects
	if load {
		open = OpenLoad
	}
	a, err := open(f, maximum)
	if err != nil {
		return nil, err
	}
	units := make([]starlark.Value, 0, len(a.Units))
	entries := []starlark.Value{}
	for unitIndex, u := range a.Units {
		records := make([]starlark.Value, 0, len(u.Records))
		for _, r := range u.Records {
			if r.Tag == CodeTag || r.Tag == PPCCodeTag || r.Tag == DataTag || r.Tag == DebugTag {
				entries = append(entries, starfile.NewRecord(starlark.StringDict{
					"path":       starlark.String(fmt.Sprintf("/unit-%d/record-%x", unitIndex, r.Offset)),
					"entry_type": starlark.String("file"), "data": r.Payload,
				}))
			}
			symbols := make([]starlark.Value, 0, len(r.Symbols))
			for _, s := range r.Symbols {
				symbols = append(symbols, starfile.NewRecord(starlark.StringDict{
					"kind": starlark.MakeUint(uint(s.Kind)), "name": s.Name, "value": starlark.MakeUint(uint(s.Value)), "offsets": fileValue(s.Offsets),
				}))
			}
			relocs := make([]starlark.Value, 0, len(r.Relocations))
			for _, v := range r.Relocations {
				relocs = append(relocs, starfile.NewRecord(starlark.StringDict{"target": starlark.MakeUint(uint(v.Target)), "offsets": v.Offsets}))
			}
			records = append(records, starfile.NewRecord(starlark.StringDict{
				"tag": starlark.MakeUint(uint(r.Tag)), "flags": starlark.MakeUint(uint(r.Flags)), "offset": starlark.MakeInt64(r.Offset),
				"raw": r.Raw, "payload": fileValue(r.Payload), "memory_size": starlark.MakeInt64(r.MemorySize),
				"symbols": starlark.NewList(symbols), "relocations": starlark.NewList(relocs),
			}))
		}
		units = append(units, starfile.NewRecord(starlark.StringDict{"name": u.Name, "raw": u.Raw, "records": starlark.NewList(records)}))
	}
	var header starlark.Value = starlark.None
	if h := a.Header; h != nil {
		libraries := []starlark.Value{}
		for _, v := range h.Libraries {
			libraries = append(libraries, v)
		}
		sizes := []starlark.Value{}
		for _, v := range h.Sizes {
			sizes = append(sizes, starlark.MakeInt64(v))
		}
		header = starfile.NewRecord(starlark.StringDict{"raw": h.Raw, "libraries": starlark.NewList(libraries), "table_size": starlark.MakeUint(uint(h.TableSize)), "first": starlark.MakeUint(uint(h.First)), "last": starlark.MakeUint(uint(h.Last)), "sizes": starlark.NewList(sizes)})
	}
	return starfile.NewRecord(starlark.StringDict{"header": header, "units": starlark.NewList(units), "entries": starlark.NewList(entries)}), nil
}
