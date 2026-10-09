package star

import (
	"github.com/tinyrange/trex/binary/softwareupdate"
	"go.starlark.net/starlark"
)

func softwareUpdateCatalogBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	if err := starlark.UnpackArgs("software_update_catalog", args, kwargs, "source", &source); err != nil {
		return nil, err
	}
	view, err := newBinaryByteView(source)
	if err != nil {
		return nil, err
	}
	result, err := softwareupdate.Catalog(view)
	if err != nil {
		return nil, err
	}
	items := make([]starlark.Value, len(result))
	for i, p := range result {
		items[i], err = plistValue(p)
		if err != nil {
			return nil, err
		}
	}
	return starlark.NewList(items), nil
}
func softwareUpdateDistributionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	if err := starlark.UnpackArgs("software_update_distribution", args, kwargs, "source", &source); err != nil {
		return nil, err
	}
	view, err := newBinaryByteView(source)
	if err != nil {
		return nil, err
	}
	result, err := softwareupdate.Distribution(view)
	if err != nil {
		return nil, err
	}
	return plistValue(result)
}
