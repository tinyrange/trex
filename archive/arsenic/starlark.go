package arsenic

import (
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum, block := 256<<20, 16<<20
	if err := starlark.UnpackArgs("arsenic", args, kwargs, "file", &value, "maximum_decoded_bytes?", &maximum, "maximum_block_bytes?", &block); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("arsenic: expected file")
	}
	if maximum < 0 || file.Size() > int64(maximum) {
		return nil, fmt.Errorf("arsenic: stored size limit")
	}
	input, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	out, err := Decode(input, maximum, block)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: out}, nil
}
