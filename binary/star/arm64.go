package star

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"golang.org/x/arch/arm64/arm64asm"
)

// arm64DisassembleBuiltin exposes bounded instruction inspection without host tools.
func arm64DisassembleBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var offset int64
	var address uint64
	count := 32
	if err := starlark.UnpackArgs("arm64_disassemble", args, kwargs, "source", &source, "offset?", &offset, "address?", &address, "count?", &count); err != nil {
		return nil, err
	}
	v, err := newBinaryByteView(source)
	if err != nil {
		return nil, err
	}
	if count < 1 || count > 4096 || offset < 0 || offset > v.size || int64(count)*4 > v.size-offset || address&3 != 0 || address > ^uint64(0)-uint64(count)*4 {
		return nil, fmt.Errorf("arm64_disassemble: invalid instruction range")
	}
	rows := make([]starlark.Value, count)
	for i := range rows {
		var b [4]byte
		if _, err := v.ReadAt(b[:], offset+int64(i)*4); err != nil {
			return nil, err
		}
		inst, err := arm64asm.Decode(b[:])
		text := inst.String()
		if err != nil {
			text = "unknown"
		}
		fields := starlark.StringDict{"address": starlark.MakeUint64(address + uint64(i)*4), "bytes": starlark.Bytes(b[:]), "instruction": starlark.String(text)}
		for _, arg := range inst.Args {
			if rel, ok := arg.(arm64asm.PCRel); ok {
				pc := address + uint64(i)*4
				if inst.Op == arm64asm.ADRP {
					pc &^= 4095
				}
				fields["target"] = starlark.MakeUint64(pc + uint64(rel))
			}
		}
		rows[i] = starfile.NewRecord(fields)
	}
	return starlark.NewList(rows), nil
}
