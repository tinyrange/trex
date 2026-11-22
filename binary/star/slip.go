package star

import (
	"fmt"
	binaryapi "github.com/tinyrange/trex/binary"
	"go.starlark.net/starlark"
)

func slipEncodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 65536
	if err := starlark.UnpackArgs("slip_encode", args, kwargs, "value", &value, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum < 1 || maximum > 1<<20 {
		return nil, fmt.Errorf("slip_encode: maximum must be1..1MiB")
	}
	data, err := bytesForBinaryValueLimited(value, int64(maximum))
	if err != nil {
		return nil, err
	}
	data, err = binaryapi.SLIPEncode(data, maximum)
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(data), nil
}

func slipDecodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 65536
	if err := starlark.UnpackArgs("slip_decode", args, kwargs, "value", &value, "maximum?", &maximum); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(value, 16<<20)
	if err != nil {
		return nil, err
	}
	packets, tail, err := binaryapi.SLIPDecode(data, maximum)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(packets))
	for i, p := range packets {
		values[i] = starlark.Bytes(p)
	}
	return starlark.Tuple{starlark.NewList(values), starlark.Bytes(tail)}, nil
}
