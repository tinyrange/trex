package amd64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"math"
	"sync/atomic"

	"golang.org/x/arch/x86/x86asm"
)

func fetchInstruction(memory cpu.Memory, pc uint64) ([15]byte, int, error) {
	// A concrete portable AddressSpace does not retain the destination. Keep
	// this buffer separate from the generic interface path so it stays on the
	// stack rather than allocating once per guest instruction.
	if space, ok := memory.(*cpu.AddressSpace); ok {
		var code [15]byte
		if err := space.ReadMemory(pc, code[:], cpu.Execute); err == nil {
			return code, len(code), nil
		}
	}
	return fetchInstructionGeneric(memory, pc)
}

func fetchInstructionGeneric(memory cpu.Memory, pc uint64) ([15]byte, int, error) {
	var code [15]byte
	if err := memory.ReadMemory(pc, code[:], cpu.Execute); err == nil {
		return code, len(code), nil
	}
	// A valid short instruction can end at a mapping, protection, or address
	// boundary. Fetch only the accessible prefix if the full read fails.
	count := 0
	for count < len(code) && pc <= math.MaxUint64-uint64(count) {
		if err := memory.ReadMemory(pc+uint64(count), code[count:count+1], cpu.Execute); err != nil {
			if count == 0 {
				return code, 0, err
			}
			break
		}
		count++
	}
	return code, count, nil
}

// This bounded cache contains only immutable decoding results, never guest
// addresses, memory, registers, or effects. Fetch and execute permission checks
// still occur on every step. Comparing all fetched bytes handles modified code,
// remapping, snapshots, and different address spaces without invalidation hooks.
// Sharing pure decode results also keeps CPU's value/snapshot semantics intact.
var instructionCache [65536]atomic.Pointer[decodedInstruction]

type decodedInstruction struct {
	code  [15]byte
	count int
	inst  x86asm.Inst
}

// The returned instruction is shared and read-only, including its operands.
// Consumers must not modify it; cache replacement allocates a different entry.
func decodeInstruction(code [15]byte, count int) (*x86asm.Inst, error) {
	hash := binary.LittleEndian.Uint64(code[:8]) ^ binary.LittleEndian.Uint64(code[7:])
	hash ^= hash >> 30
	hash *= 0xbf58476d1ce4e5b9
	hash ^= hash >> 27
	slot := &instructionCache[hash%uint64(len(instructionCache))]
	if cached := slot.Load(); cached != nil && cached.count == count && cached.code == code {
		return &cached.inst, nil
	}
	inst, err := x86asm.Decode(code[:count], 64)
	decoded := &decodedInstruction{code: code, count: count, inst: inst}
	if err == nil && inst.Op != 0 {
		slot.Store(decoded)
	}
	return &decoded.inst, err
}
