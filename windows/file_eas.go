package windows

import (
	"github.com/tinyrange/trex/filesystem"
	"go.starlark.net/starlark"
)

func decodeFileEAsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("decode_file_eas", args, kwargs, "data", &value); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(value, 65536)
	if err != nil {
		return nil, err
	}
	eas, err := filesystem.DecodeFileFullEAInformation(data)
	if err != nil {
		return nil, err
	}
	result := make([]starlark.Value, 0, len(eas))
	for _, ea := range eas {
		d := starlark.NewDict(3)
		_ = d.SetKey(starlark.String("name"), starlark.String(ea.Name))
		_ = d.SetKey(starlark.String("flags"), starlark.MakeInt(int(ea.Flags)))
		_ = d.SetKey(starlark.String("value"), starlark.Bytes(ea.Value))
		result = append(result, d)
	}
	return starlark.NewList(result), nil
}
