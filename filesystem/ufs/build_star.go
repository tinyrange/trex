package ufs

import (
	"github.com/tinyrange/trex/filesystem/unixfs"
	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func BuildBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	options := BuildOptions{Layout: "raw", Timestamp: 1700000000}
	if err := starlark.UnpackArgs("ffs_build", args, kwargs, "entries", &value, "size?", &options.Size, "extra?", &options.Extra, "layout?", &options.Layout, "timestamp?", &options.Timestamp); err != nil {
		return nil, err
	}
	entries, err := unixfs.ParseEntries(value)
	if err != nil {
		return nil, err
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	image, err := Build(resources.Context(), entries, options)
	if err != nil {
		return nil, err
	}
	return starfile.NewReader("FFS1 image", image), nil
}
