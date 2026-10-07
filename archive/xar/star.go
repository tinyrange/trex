package xar

import (
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("xar", 20, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < 4 || string(p[:4]) != "xar!" {
			return nil, auto.ErrNoMatch
		}
		a, err := Open(r, o.MaxEntries)
		if err != nil {
			return nil, err
		}
		var entries []auto.Entry
		for _, e := range a.Entries {
			kind := e.Kind
			if kind == "hardlink" {
				kind = "file"
			}
			entries = append(entries, auto.Entry{Name: e.Path, Kind: kind, Reader: e.Data, Attributes: map[string]any{"mode": e.Mode, "uid": e.UID, "gid": e.GID, "target": e.Target, "encoding": e.Encoding}})
		}
		return auto.Tree(entries, o)
	})
}
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 100000
	if err := starlark.UnpackArgs("xar", args, kwargs, "file", &value, "maximum_entries?", &maximum); err != nil {
		return nil, err
	}
	r, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("xar: expected file")
	}
	a, err := Open(r, maximum)
	if err != nil {
		return nil, err
	}
	var entries, paths []starlark.Value
	index := map[string]starlark.Value{}
	for i := range a.Entries {
		e := &a.Entries[i]
		var raw, data starlark.Value = starlark.None, starlark.None
		var size int64
		if e.Raw != nil {
			raw = starfile.NewReader(e.Path+".stored", e.Raw)
		}
		if e.Data != nil {
			data = starfile.NewReader(e.Path, e.Data)
			size = e.Data.Size()
		}
		verify := starlark.NewBuiltin("xar.entry.verify", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("verify", args, kwargs); err != nil {
				return nil, err
			}
			if err := e.Verify(); err != nil {
				return nil, err
			}
			return starlark.None, nil
		})
		v := starfile.NewRecord(starlark.StringDict{"path": starlark.String(e.Path), "id": starlark.String(e.ID), "kind": starlark.String(e.Kind), "mode": starlark.MakeUint64(e.Mode), "uid": starlark.MakeUint64(e.UID), "gid": starlark.MakeUint64(e.GID), "target": starlark.String(e.Target), "encoding": starlark.String(e.Encoding), "raw": raw, "data": data, "size": starlark.MakeInt64(size), "verify": verify})
		entries = append(entries, v)
		paths = append(paths, starlark.String(e.Path))
		index[e.Path] = v
	}
	find := starlark.NewBuiltin("xar.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs("find", args, kwargs, "path", &name); err != nil {
			return nil, err
		}
		if v := index[name]; v != nil {
			return v, nil
		}
		return starlark.None, nil
	})
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(entries), "files": starlark.NewList(paths), "toc": starlark.Bytes(a.TOC), "heap": starfile.NewReader("heap", a.Heap), "find": find}), nil
}
