package amd64

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/emulator/cpu"
	"golang.org/x/arch/x86/x86asm"
)

// fxrstor restores the admitted legacy SIMD context atomically. The processor
// does not yet execute x87/MMX operations; a non-reset x87 environment is an
// explicit unsupported state, never silently discarded. Empty register payloads
// and reserved/software-owned bytes do not affect the architectural environment.
func (c *CPU) fxrstor(memory cpu.Memory, inst *x86asm.Inst, next uint64) error {
	operand, ok := inst.Args[0].(x86asm.Mem)
	if !ok {
		return fmt.Errorf("amd64: FXRSTOR requires a memory operand")
	}
	address, err := c.address(operand, next, inst.AddrSize)
	if err != nil {
		return err
	}
	if address&15 != 0 {
		return fmt.Errorf("amd64: FXRSTOR source %#x is not 16-byte aligned", address)
	}
	var state [416]byte
	if err := memory.ReadMemory(address, state[:], cpu.Read); err != nil {
		return err
	}
	if binary.LittleEndian.Uint16(state[:2]) != 0x037f || binary.LittleEndian.Uint16(state[2:4]) != 0 || state[4] != 0 || binary.LittleEndian.Uint16(state[6:8])&0x7ff != 0 || binary.LittleEndian.Uint64(state[8:16]) != 0 || binary.LittleEndian.Uint64(state[16:24]) != 0 {
		return fmt.Errorf("amd64: FXRSTOR non-reset x87 environment is not implemented")
	}
	restored := *c
	if err := restored.setMXCSR(uint64(binary.LittleEndian.Uint32(state[24:28]))); err != nil {
		return err
	}
	for index := range restored.xmm {
		copy(restored.xmm[index][:], state[160+16*index:176+16*index])
	}
	*c = restored
	return nil
}
