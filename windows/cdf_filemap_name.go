package windows

import (
	"github.com/tinyrange/trex/windows/cdf"
	"go.starlark.net/starlark"
)

func cdfFileMapNameBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	root := "/Windows"
	if err := starlark.UnpackArgs("cdf_filemap_name", args, kwargs, "path", &path, "windows_root?", &root); err != nil {
		return nil, err
	}
	name, err := cdf.FileMapName(path, root)
	if err != nil {
		return nil, err
	}
	return starlark.String(name), nil
}
