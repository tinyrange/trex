package cc

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"j5.nz/cc/kernelvm"
)

func kernelSymbolBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var address uint64
	if err := starlark.UnpackArgs("cc.kernel_symbol", args, kwargs, "kernel", &value, "address", &address); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("cc.kernel_symbol: expected ELF file")
	}
	symbol, err := kernelvm.SymbolAt(source, source.Size(), address)
	if err != nil {
		return nil, err
	}
	if symbol == nil {
		return starlark.None, nil
	}
	return starfile.NewRecord(starlark.StringDict{"name": starlark.String(symbol.Name), "address": starlark.MakeUint64(symbol.Address), "size": starlark.MakeUint64(symbol.Size), "offset": starlark.MakeUint64(symbol.Offset)}), nil
}
