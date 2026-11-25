package star

import (
	"fmt"

	"github.com/tinyrange/trex/filesystem/unixfs"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// binaryZerosBuiltin exposes the existing bounded reader without allocating a
// buffer proportional to logical size or introducing any host-path dependency.
func binaryZerosBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var size int64
	if err := starlark.UnpackArgs("zeros", args, kwargs, "size", &size); err != nil {
		return nil, err
	}
	if size < 0 {
		return nil, fmt.Errorf("zeros: size must be nonnegative")
	}
	return starfile.NewReader("zeros", unixfs.Zero(size)), nil
}
