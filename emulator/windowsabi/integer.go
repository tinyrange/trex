// Package windowsabi marshals Windows calls independently of CPU execution and
// system API policy. Integer and pointer arguments retain their full width.
package windowsabi

import (
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/emulator/cpu"
)

var integerRegisters = [...]string{"rcx", "rdx", "r8", "r9"}

// PrepareAMD64IntegerCall creates the callee-entry stack frame, including the
// return address, four home slots, stack arguments, and 16-byte caller alignment.
// Float, vector and aggregate classification is deliberately not implied by
// this integer-only API. See Microsoft's x64 calling convention specification:
// https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
func PrepareAMD64IntegerCall(processor cpu.Processor, memory cpu.Memory, address, stackTop, returnAddress uint64, arguments []uint64) error {
	if processor.Architecture().Name != "amd64" {
		return fmt.Errorf("windows ABI: AMD64 processor required")
	}
	if len(arguments) > 4096 {
		return fmt.Errorf("windows ABI: too many arguments")
	}
	space := uint64(32 + max(0, len(arguments)-4)*8)
	if stackTop < space+8 {
		return fmt.Errorf("windows ABI: stack frame underflows")
	}
	callerSP := (stackTop - space) &^ 15
	if callerSP < 8 {
		return fmt.Errorf("windows ABI: return slot underflows")
	}
	sp := callerSP - 8
	frame := make([]byte, stackTop-sp)
	binary.LittleEndian.PutUint64(frame, returnAddress)
	for i := 4; i < len(arguments); i++ {
		binary.LittleEndian.PutUint64(frame[40+(i-4)*8:], arguments[i])
	}
	if err := memory.WriteMemory(sp, frame); err != nil {
		return err
	}
	for i := 0; i < min(4, len(arguments)); i++ {
		if err := processor.SetRegister(integerRegisters[i], arguments[i]); err != nil {
			return err
		}
	}
	if err := processor.SetRegister("rsp", sp); err != nil {
		return err
	}
	processor.SetPC(address)
	return nil
}

// AMD64IntegerArguments reads an intercepted function's arguments at entry,
// before that function has modified RSP or spilled its register parameters.
func AMD64IntegerArguments(processor cpu.Processor, memory cpu.Memory, count int) ([]uint64, error) {
	if processor.Architecture().Name != "amd64" {
		return nil, fmt.Errorf("windows ABI: AMD64 processor required")
	}
	if count < 0 || count > 4096 {
		return nil, fmt.Errorf("windows ABI: invalid argument count")
	}
	sp, err := processor.Register("rsp")
	if err != nil {
		return nil, err
	}
	args := make([]uint64, count)
	for i := range args {
		if i < 4 {
			args[i], err = processor.Register(integerRegisters[i])
		} else {
			offset := uint64(40 + (i-4)*8)
			if sp > ^uint64(0)-offset {
				return nil, fmt.Errorf("windows ABI: argument address overflows")
			}
			var data [8]byte
			err = memory.ReadMemory(sp+offset, data[:], cpu.Read)
			args[i] = binary.LittleEndian.Uint64(data[:])
		}
		if err != nil {
			return nil, err
		}
	}
	return args, nil
}

// ReturnAMD64Integer completes a semantic function hook. On Win64 the caller
// owns shadow space and stack-argument cleanup; only the return slot is popped.
func ReturnAMD64Integer(processor cpu.Processor, memory cpu.Memory, value uint64) error {
	if processor.Architecture().Name != "amd64" {
		return fmt.Errorf("windows ABI: AMD64 processor required")
	}
	sp, err := processor.Register("rsp")
	if err != nil {
		return err
	}
	if sp > ^uint64(0)-8 {
		return fmt.Errorf("windows ABI: stack pointer overflows")
	}
	var data [8]byte
	if err := memory.ReadMemory(sp, data[:], cpu.Read); err != nil {
		return err
	}
	if err := processor.SetRegister("rax", value); err != nil {
		return err
	}
	if err := processor.SetRegister("rsp", sp+8); err != nil {
		return err
	}
	processor.SetPC(binary.LittleEndian.Uint64(data[:]))
	return nil
}
