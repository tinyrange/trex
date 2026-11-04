package windows

import (
	"fmt"

	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func csiCompositionBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var root starlark.Bytes
	var resolve starlark.Callable
	limit := 1 << 20
	if err := starlark.UnpackArgs("csi_composition", args, kwargs, "root", &root, "resolve", &resolve, "work_limit?", &limit); err != nil {
		return nil, err
	}
	identity, err := uup.ParseCSIIdentity([]byte(root))
	if err != nil {
		return nil, err
	}
	members, err := uup.CalculateCSIComposition(identity, func(id uup.AssemblyIdentity) (*uup.AssemblyManifest, error) {
		canonical, err := uup.FormatCSIIdentity(id)
		if err != nil {
			return nil, err
		}
		value, err := starlark.Call(thread, resolve, starlark.Tuple{starlark.Bytes(canonical)}, nil)
		if err != nil {
			return nil, err
		}
		if value == starlark.None {
			return nil, fmt.Errorf("missing exact component %q", id.Name)
		}
		manifest, _, err := cbsManifestForValue(value, 64<<20)
		return manifest, err
	}, limit)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(members))
	for i, member := range members {
		canonical, err := uup.FormatCSIIdentity(member.Identity)
		if err != nil {
			return nil, err
		}
		values[i] = starvalue.NewRecord(starlark.StringDict{"identity": starlark.Bytes(canonical), "disposition": starlark.MakeUint64(uint64(member.Disposition))})
	}
	return starlark.NewList(values), nil
}
