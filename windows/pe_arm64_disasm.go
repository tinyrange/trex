package windows

import (
	"fmt"
	"strings"

	"go.starlark.net/starlark"
	"golang.org/x/arch/arm64/arm64asm"
)

// peDisasmARM64 keeps undecodable words and truncated tails visible without
// reading beyond the caller's bounded window. PC-relative operands expose RVAs.
func peDisasmARM64(data []byte, rva uint64) *starlark.List {
	rows := make([]starlark.Value, 0, (len(data)+3)/4)
	for len(data) != 0 {
		size := min(4, len(data))
		inst, err := arm64asm.Decode(data[:size])
		text, op := fmt.Sprintf(".byte %x", data[:size]), ""
		operands := starlark.NewList(nil)
		if err == nil {
			text, op = arm64asm.GNUSyntax(inst), strings.ToLower(inst.Op.String())
			for _, arg := range inst.Args {
				if arg == nil {
					break
				}
				operand := starlark.NewDict(3)
				operand.SetKey(starlark.String("text"), starlark.String(arg.String()))
				kind := "other"
				switch value := arg.(type) {
				case arm64asm.PCRel:
					kind = "relative"
					base := rva
					if inst.Op == arm64asm.ADRP {
						base &^= 4095
					}
					operand.SetKey(starlark.String("target"), starlark.MakeUint64(uint64(int64(base)+int64(value))))
				case arm64asm.Reg, arm64asm.RegSP:
					kind = "register"
				case arm64asm.MemImmediate, arm64asm.MemExtend:
					kind = "memory"
				}
				operand.SetKey(starlark.String("kind"), starlark.String(kind))
				operands.Append(operand)
			}
		}
		row := starlark.NewDict(6)
		for name, value := range map[string]starlark.Value{
			"rva": starlark.MakeUint64(rva), "size": starlark.MakeInt(size),
			"bytes": starlark.Bytes(data[:size]), "text": starlark.String(text),
			"op": starlark.String(op), "operands": operands,
		} {
			row.SetKey(starlark.String(name), value)
		}
		rows = append(rows, row)
		data, rva = data[size:], rva+uint64(size)
	}
	return starlark.NewList(rows)
}
