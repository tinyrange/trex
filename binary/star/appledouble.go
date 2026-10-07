package star

import (
	"fmt"
	"github.com/tinyrange/trex/binary/appledouble"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func appleDoubleBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("appledouble", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("appledouble: expected file")
	}
	entries, err := appledouble.Open(file)
	if err != nil {
		return nil, err
	}
	out := starlark.NewDict(len(entries))
	for _, e := range entries {
		if err := out.SetKey(starlark.MakeUint(uint(e.ID)), starfile.NewReader("AppleDouble entry", e.Data)); err != nil {
			return nil, err
		}
	}
	return out, nil
}
