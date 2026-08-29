package debug

import (
	"fmt"

	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"golang.org/x/arch/x86/x86asm"
)

func DisassembleBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var input starlark.Value
	var address uint64
	architecture := "i386"
	maximum := 64 << 20
	count := -1
	if err := starlark.UnpackArgs("disassemble", args, kwargs,
		"data", &input, "address?", &address, "architecture?", &architecture, "maximum?", &maximum, "count?", &count,
	); err != nil {
		return nil, err
	}
	if maximum < 0 || maximum > 1<<30 || count < -1 || count > 1<<20 {
		return nil, fmt.Errorf("disassemble: invalid resource limit")
	}
	data, err := starfile.BytesForValue(input, int64(maximum))
	if err != nil {
		return nil, err
	}
	mode := 32
	switch architecture {
	case "i8086", "i386:x86-16", "x86-16":
		mode = 16
	case "i386", "i386:x86-32", "x86":
	case "x86_64", "i386:x86-64", "amd64":
		mode = 64
	default:
		return nil, fmt.Errorf("disassemble: unsupported architecture %q", architecture)
	}
	values := make([]starlark.Value, 0, len(data)/2)
	for offset := 0; offset < len(data) && (count < 0 || len(values) < count); {
		instruction, err := x86asm.Decode(data[offset:], mode)
		if err != nil {
			return nil, fmt.Errorf("disassemble: decode at %#x: %w", address+uint64(offset), err)
		}
		if instruction.Len <= 0 || instruction.Len > len(data)-offset {
			return nil, fmt.Errorf("disassemble: invalid instruction length at %#x", address+uint64(offset))
		}
		pc := address + uint64(offset)
		flow := "other"
		target := starlark.Value(starlark.None)
		switch instruction.Op {
		case x86asm.CALL, x86asm.LCALL:
			flow = "call"
		case x86asm.JMP, x86asm.LJMP:
			flow = "jump"
		case x86asm.RET, x86asm.LRET, x86asm.IRET, x86asm.IRETD, x86asm.IRETQ:
			flow = "return"
		default:
			if instruction.Op.String() != "" && instruction.Op.String()[0] == 'J' {
				flow = "branch"
			}
		}
		if relative, ok := instruction.Args[0].(x86asm.Rel); ok {
			target = starlark.MakeUint64(uint64(int64(pc) + int64(instruction.Len) + int64(relative)))
		}
		normalized := append([]byte(nil), data[offset:offset+instruction.Len]...)
		if instruction.PCRel > 0 {
			clear(normalized[instruction.PCRelOff : instruction.PCRelOff+instruction.PCRel])
		}
		values = append(values, starvalue.NewRecord(starlark.StringDict{
			"address":          starlark.MakeUint64(pc),
			"bytes":            starlark.Bytes(data[offset : offset+instruction.Len]),
			"flow":             starlark.String(flow),
			"length":           starlark.MakeInt(instruction.Len),
			"normalized_bytes": starlark.Bytes(normalized),
			"op":               starlark.String(instruction.Op.String()),
			"relative_offset":  starlark.MakeInt(instruction.PCRelOff),
			"relative_size":    starlark.MakeInt(instruction.PCRel),
			"target":           target,
			"text":             starlark.String(x86asm.IntelSyntax(instruction, pc, nil)),
		}))
		offset += instruction.Len
	}
	return starlark.NewList(values), nil
}
