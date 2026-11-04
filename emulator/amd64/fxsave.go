package amd64

import (
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/emulator/cpu"
	"golang.org/x/arch/x86/x86asm"
)

// fxsave records the processor's legacy floating-point/SIMD state without
// changing that state. No x87/MMX state-changing instructions are implemented
// yet, so its x87 environment is still the architectural reset environment.
// Both long-mode encodings save all sixteen XMM registers. REX.W changes only
// the x87 pointer layout; both pointers are zero in this reset environment.
func (c *CPU) fxsave(memory cpu.Memory, inst *x86asm.Inst, next uint64) error {
	operand, ok := inst.Args[0].(x86asm.Mem)
	if !ok {
		return fmt.Errorf("amd64: FXSAVE requires a memory operand")
	}
	address, err := c.address(operand, next, inst.AddrSize)
	if err != nil {
		return err
	}
	if address&15 != 0 {
		return fmt.Errorf("amd64: FXSAVE destination %#x is not 16-byte aligned", address)
	}
	// Save only the defined register area. Reserved bytes 416..463 and the
	// software-owned bytes 464..511 remain untouched; do not require read
	// permission on a write-only destination to preserve those bytes.
	var state [416]byte
	binary.LittleEndian.PutUint16(state[0:2], 0x037f) // FCW: reset
	// FSW=0, abridged FTW=0 (all empty), FOP/FIP/FDP=0. Empty x87
	// register payloads and reserved fields have a deterministic zero value.
	binary.LittleEndian.PutUint32(state[24:28], uint32(c.readMXCSR()))
	binary.LittleEndian.PutUint32(state[28:32], 0xffff) // Supported MXCSR bits.
	for index := range c.xmm {
		copy(state[160+16*index:176+16*index], c.xmm[index][:])
	}
	return memory.WriteMemory(address, state[:])
}
