package c2r

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// DatabaseBuiltin exposes the decoded literal tables for read-only inspection.
func DatabaseBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("c2r_database", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	r, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("c2r_database: expected file")
	}
	db, err := ReadDatabase(r)
	if err != nil {
		return nil, err
	}
	result := starlark.NewDict(len(db.Tables))
	names := make([]string, 0, len(db.Tables))
	for name := range db.Tables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rows := db.Tables[name]
		list := make([]starlark.Value, 0, len(rows))
		for _, row := range rows {
			cells := make(starlark.Tuple, len(row))
			for i, c := range row {
				if c.IsText {
					cells[i] = starlark.String(c.Text)
				} else {
					cells[i] = starlark.MakeInt64(c.Number)
				}
			}
			list = append(list, cells)
		}
		if err := result.SetKey(starlark.String(name), starlark.NewList(list)); err != nil {
			return nil, err
		}
	}
	result.Freeze()
	return result, nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var dv, sv starlark.Value
	if err := starlark.UnpackArgs("c2r", args, kwargs, "database", &dv, "stream", &sv); err != nil {
		return nil, err
	}
	d, ok := dv.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("c2r: expected database file")
	}
	s, ok := sv.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("c2r: expected stream file")
	}
	a, err := Open(d, s)
	if err != nil {
		return nil, err
	}
	var entries []starlark.Value
	index := map[string]starlark.Value{}
	for _, e := range a.Entries {
		var packages []starlark.Value
		for _, p := range e.Packages {
			packages = append(packages, starlark.String(p))
		}
		verify := starlark.NewBuiltin("c2r.verify", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("verify", args, kwargs); err != nil {
				return nil, err
			}
			if err := e.Verify(); err != nil {
				return nil, err
			}
			return starlark.None, nil
		})
		v := starfile.NewRecord(starlark.StringDict{"path": starlark.String(e.Path), "size": starlark.MakeInt64(e.Size()), "data": starfile.NewReader(e.Path, e), "packages": starlark.NewList(packages), "verify": verify})
		entries = append(entries, v)
		index[strings.ToLower(e.Path)] = v
	}
	find := starlark.NewBuiltin("c2r.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs("find", args, kwargs, "path", &name); err != nil {
			return nil, err
		}
		name, err := safePath(name)
		if err != nil {
			return nil, err
		}
		if v := index[strings.ToLower(name)]; v != nil {
			return v, nil
		}
		return starlark.None, nil
	})
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(entries), "find": find}), nil
}
