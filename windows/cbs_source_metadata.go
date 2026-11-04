package windows

import (
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func cbsDeploymentSourceDataBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var update string
	if err := starlark.UnpackArgs("cbs_deployment_source_data", args, kwargs, "manifest", &value, "update", &update); err != nil {
		return nil, err
	}
	manifest, _, err := cbsManifestForValue(value, 64<<20)
	if err != nil {
		return nil, err
	}
	result, err := uup.CBSDeploymentSourceData(manifest, update)
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(result), nil
}
