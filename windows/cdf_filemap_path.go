package windows

import (
	"github.com/tinyrange/trex/windows/cdf"
	"go.starlark.net/starlark"
)

func cdfFileMapPathBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, volume string
	root := "/Windows"
	if err := starlark.UnpackArgs("cdf_filemap_path", args, kwargs, "path", &path, "volume", &volume, "windows_root?", &root); err != nil {
		return nil, err
	}
	path, selector, err := cdf.FileMapPath(path, root, volume)
	if err != nil {
		return nil, err
	}
	result := starlark.NewDict(2)
	_ = result.SetKey(starlark.String("path"), starlark.String(path))
	_ = result.SetKey(starlark.String("root_selector"), starlark.MakeUint64(uint64(selector)))
	return result, nil
}
