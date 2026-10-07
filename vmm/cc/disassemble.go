package cc

import (
	"fmt"
	"github.com/tinyrange/trex/emulator/cpu"
	"go.starlark.net/starlark"
	"golang.org/x/arch/x86/x86asm"
)

// disassemble is a read-only, bounded observation of the owning guest memory.
func (i inspection) disassemble(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	size, mode := 256, 64
	if err := starlark.UnpackArgs("cc.disassemble", args, kwargs, "address", &address, "size?", &size, "mode?", &mode); err != nil {
		return nil, err
	}
	if size < 0 || size > 4096 || (mode != 16 && mode != 32 && mode != 64) || uint64(size) > ^uint64(0)-address {
		return nil, fmt.Errorf("cc: disassemble requires size 0..4096, nonwrapping address and mode 16/32/64")
	}
	var result starlark.Value
	err := i.driver.call(i.ctx, func() error {
		s, err := i.driver.pc.cpu.SystemRegisters()
		if err != nil {
			return err
		}
		b := make([]byte, size)
		if err = (efiMemory{p: i.driver.pc, system: &s}).ReadMemory(address, b, cpu.Read); err != nil {
			return err
		}
		result, err = decodeInstructions(b, address, mode)
		return err
	})
	return result, err
}

func decodeInstructions(b []byte, address uint64, mode int) (starlark.Value, error) {
	out := []starlark.Value{}
	for off := 0; off < len(b); {
		inst, err := x86asm.Decode(b[off:], mode)
		if err != nil || inst.Len == 0 || inst.Op == 0 {
			row := starlark.NewDict(2)
			_ = row.SetKey(starlark.String("address"), starlark.MakeUint64(address+uint64(off)))
			_ = row.SetKey(starlark.String("error"), starlark.String("invalid or truncated instruction"))
			out = append(out, row)
			break
		}
		pc := address + uint64(off)
		row := starlark.NewDict(3)
		_ = row.SetKey(starlark.String("address"), starlark.MakeUint64(pc))
		_ = row.SetKey(starlark.String("size"), starlark.MakeInt(inst.Len))
		_ = row.SetKey(starlark.String("text"), starlark.String(x86asm.IntelSyntax(inst, pc, nil)))
		out = append(out, row)
		off += inst.Len
	}
	return starlark.NewList(out), nil
}
