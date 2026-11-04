package windows

import (
	"fmt"

	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func csiMOFEquivalentBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var left, right starlark.Value
	if err := starlark.UnpackArgs("csi_mof_equivalent", args, kwargs, "left", &left, "right", &right); err != nil {
		return nil, err
	}
	var manifests [2]*uup.AssemblyManifest
	for i, v := range []starlark.Value{left, right} {
		data, err := bytesForBinaryValueLimited(v, 16<<20)
		if err != nil {
			return nil, err
		}
		manifests[i], err = uup.ParseAssemblyManifestBytes(data)
		if err != nil {
			return nil, fmt.Errorf("csi_mof_equivalent manifest %d: %w", i, err)
		}
	}
	equal, err := uup.CSIMOFEquivalent(manifests[0], manifests[1])
	if err != nil {
		return nil, fmt.Errorf("csi_mof_equivalent: %w", err)
	}
	return starlark.Bool(equal), nil
}
