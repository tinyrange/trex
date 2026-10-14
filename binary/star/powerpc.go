package star

import (
	"encoding/json"
	"fmt"
	binaryapi "github.com/tinyrange/trex/binary"
	starjson "go.starlark.net/lib/json"
	"go.starlark.net/starlark"
)

func powerPCInstructionsBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var offset int64
	size := int64(256)
	address := starlark.Value(starlark.MakeInt(0))
	order := "big"
	maximum := 4096
	if err := starlark.UnpackArgs("ppc_instructions", args, kwargs, "source", &source, "offset?", &offset, "size?", &size, "address?", &address, "byte_order?", &order, "maximum?", &maximum); err != nil {
		return nil, err
	}
	view, err := newBinaryByteView(source)
	if err != nil {
		return nil, err
	}
	var pc uint64
	if err := starlark.AsInt(address, &pc); err != nil {
		return nil, fmt.Errorf("ppc_instructions: address: %w", err)
	}
	records, err := binaryapi.PowerPCInstructions(view, offset, size, pc, order, maximum)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		return nil, err
	}
	return starlark.Call(thread, starjson.Module.Members["decode"], starlark.Tuple{starlark.String(encoded)}, nil)
}
