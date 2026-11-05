package windows

import (
	"fmt"

	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func cbsComponentOwnersBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var installed, pinned, changes *starlark.List
	if err := starlark.UnpackArgs("cbs_component_owners", args, kwargs, "installed", &installed, "pinned", &pinned, "changes", &changes); err != nil {
		return nil, err
	}
	if installed.Len() > 1<<20 || pinned.Len() > 1<<20 || changes.Len() > 1<<20 || installed.Len()+pinned.Len()+changes.Len() > 1<<20 {
		return nil, fmt.Errorf("CBS component owner count exceeds bound")
	}
	totalBytes := 0
	decode := func(v starlark.Value, change bool) (uup.CBSComponentOwnerChange, error) {
		var out uup.CBSComponentOwnerChange
		d, ok := v.(*starlark.Dict)
		if !ok {
			return out, fmt.Errorf("CBS component owner must be a dict")
		}
		var source starlark.Value
		var elevation uint32
		fields := []any{"source", &source, "elevation", &elevation}
		if change {
			fields = append(fields, "action", &out.Action)
		}
		if err := starlark.UnpackArgs("CBS component owner", nil, d.Items(), fields...); err != nil {
			return out, err
		}
		if source == starlark.None {
			out.Owner.Anonymous = true
		} else {
			name, ok := starlark.AsString(source)
			if !ok {
				return out, fmt.Errorf("CBS component source must be a string or None")
			}
			totalBytes += len(name)
			if len(name) > 64<<10 || totalBytes > 64<<20 {
				return out, fmt.Errorf("CBS component source data exceeds bound")
			}
			out.Owner.Name = name
		}
		out.Owner.Elevation = elevation
		return out, nil
	}
	var base uup.CBSComponentOwners
	for v := range installed.Elements() {
		o, err := decode(v, false)
		if err != nil {
			return nil, err
		}
		base.Installed = append(base.Installed, o.Owner)
	}
	for v := range pinned.Elements() {
		o, err := decode(v, false)
		if err != nil {
			return nil, err
		}
		base.Pinned = append(base.Pinned, o.Owner)
	}
	events := make([]uup.CBSComponentOwnerChange, 0, changes.Len())
	for v := range changes.Elements() {
		o, err := decode(v, true)
		if err != nil {
			return nil, err
		}
		events = append(events, o)
	}
	result, err := uup.ResolveCBSComponentOwners(base, events)
	if err != nil {
		return nil, err
	}
	encode := func(owners []uup.CBSComponentOwner) *starlark.List {
		out := make([]starlark.Value, 0, len(owners))
		for _, o := range owners {
			var source starlark.Value = starlark.String(o.Name)
			if o.Anonymous {
				source = starlark.None
			}
			d := starlark.NewDict(2)
			_ = d.SetKey(starlark.String("source"), source)
			_ = d.SetKey(starlark.String("elevation"), starlark.MakeUint64(uint64(o.Elevation)))
			out = append(out, d)
		}
		return starlark.NewList(out)
	}
	return starvalue.NewRecord(starlark.StringDict{"installed": encode(result.Installed), "pinned": encode(result.Pinned)}), nil
}
