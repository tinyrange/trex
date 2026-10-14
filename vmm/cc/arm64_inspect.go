package cc

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/script/value"
	"github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

func (d *arm64Driver) readARM64Instruction(pc uint64) (uint32, error) {
	sctlr, err := d.cpu.SystemRegister(0xc080)
	if err != nil {
		return 0, err
	}
	var data []byte
	if sctlr&1 == 0 {
		data, err = d.readARM64Physical(pc, 4)
	} else {
		tcr, e := d.cpu.SystemRegister(0xc102)
		if e != nil {
			return 0, e
		}
		ttbr0, e := d.cpu.SystemRegister(0xc100)
		if e != nil {
			return 0, e
		}
		ttbr1, e := d.cpu.SystemRegister(0xc101)
		if e != nil {
			return 0, e
		}
		walker := vmm.ARM64Translation{TCR: tcr, TTBR0: ttbr0, TTBR1: ttbr1, ReadPhysical: d.readARM64Physical}
		data, err = walker.Read(pc, 4)
	}
	if err != nil {
		return 0, fmt.Errorf("fetch MMIO instruction at %#x: %w", pc, err)
	}
	return binary.LittleEndian.Uint32(data), nil
}

// Stopped ARM64 memory remains owned by the session until Close, allowing
// bounded inspection of hardware-breakpoint and failure evidence.
func (d *arm64Driver) Extension(_ context.Context, name string) (starlark.Value, error) {
	if name != d.BackendID() {
		return nil, fmt.Errorf("unknown ARM64 extension %q", name)
	}
	read := func(virtual bool) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		return func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var address uint64
			var size int
			if err := starlark.UnpackArgs("cc.read_memory", args, kwargs, "address", &address, "size", &size); err != nil {
				return nil, err
			}
			d.mu.Lock()
			defer d.mu.Unlock()
			select {
			case <-d.done:
			default:
				return nil, fmt.Errorf("ARM64 inspection requires a stopped VM")
			}
			if d.resourcesClosed {
				return nil, fmt.Errorf("ARM64 VM is closed")
			}
			var data []byte
			var err error
			sctlr, haveSCTLR := d.registers["sctlr"].(uint64)
			if virtual && !haveSCTLR {
				return nil, fmt.Errorf("ARM64 inspection lacks SCTLR_EL1")
			}
			if virtual && sctlr&1 != 0 {
				tcr, haveTCR := d.registers["tcr"].(uint64)
				ttbr0, have0 := d.registers["ttbr0"].(uint64)
				ttbr1, have1 := d.registers["ttbr1"].(uint64)
				if !haveTCR || !have0 || !have1 {
					return nil, fmt.Errorf("ARM64 inspection lacks translation registers")
				}
				t := vmm.ARM64Translation{TCR: tcr, TTBR0: ttbr0, TTBR1: ttbr1, ReadPhysical: d.readARM64Physical}
				data, err = t.Read(address, size)
			} else {
				data, err = d.readARM64Physical(address, size)
			}
			if err != nil {
				return nil, err
			}
			return starlark.Bytes(string(data)), nil
		}
	}
	return value.NewRecord(starlark.StringDict{"read_physical": starlark.NewBuiltin("cc.read_physical", read(false)), "read_virtual": starlark.NewBuiltin("cc.read_virtual", read(true))}), nil
}

func (d *arm64Driver) readARM64Physical(address uint64, size int) ([]byte, error) {
	if size < 0 || size > 65536 || address < d.base || address-d.base > uint64(len(d.ram)) || uint64(size) > uint64(len(d.ram))-(address-d.base) {
		return nil, fmt.Errorf("ARM64 physical read outside RAM or size limit")
	}
	return d.ram[address-d.base : address-d.base+uint64(size)], nil
}
