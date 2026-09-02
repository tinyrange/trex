package windows

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const (
	amd64UnwindPushNonvol    = 0
	amd64UnwindAllocLarge    = 1
	amd64UnwindAllocSmall    = 2
	amd64UnwindSetFPReg      = 3
	amd64UnwindSaveNonvol    = 4
	amd64UnwindSaveNonvolFar = 5
	amd64UnwindSaveXMM128    = 8
	amd64UnwindSaveXMM128Far = 9
	amd64UnwindPushMachFrame = 10

	amd64UnwindChainInfo    = 4
	amd64MaximumUnwindCodes = 256
)

var amd64RegisterNames = [...]string{
	"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}

type amd64RuntimeFunction struct {
	begin, end, unwind uint32
}

type amd64UnwindState struct {
	registers [16]uint64
	stack     []byte
	stackBase uint64
	stackEnd  uint64
	rsp       uint64
	returnAt  uint64
}

func (p *windowsPE) amd64UnwindBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var rva, stackBase, stackPointer uint64
	var stack starlark.Bytes
	var registerValues *starlark.Dict
	if err := starlark.UnpackArgs(
		"amd64_unwind", args, kwargs,
		"rva", &rva,
		"stack", &stack,
		"stack_start", &stackBase,
		"stack_pointer", &stackPointer,
		"registers?", &registerValues,
	); err != nil {
		return nil, err
	}
	if rva > uint64(^uint32(0)) {
		return nil, fmt.Errorf("amd64_unwind: RVA %#x exceeds PE32+ range", rva)
	}
	if uint64(len(stack)) > ^uint64(0)-stackBase {
		return nil, fmt.Errorf("amd64_unwind: stack address range overflows")
	}
	state := amd64UnwindState{
		stack:     []byte(stack),
		stackBase: stackBase,
		stackEnd:  stackBase + uint64(len(stack)),
		rsp:       stackPointer,
	}
	state.registers[4] = stackPointer
	if registerValues != nil {
		for _, item := range registerValues.Items() {
			name, ok := starlark.AsString(item[0])
			if !ok {
				return nil, fmt.Errorf("amd64_unwind: register name has type %s, want string", item[0].Type())
			}
			index := amd64RegisterIndex(name)
			if index < 0 {
				return nil, fmt.Errorf("amd64_unwind: unknown register %q", name)
			}
			var value uint64
			if err := starlark.AsInt(item[1], &value); err != nil {
				return nil, fmt.Errorf("amd64_unwind: register %s has type %s, want int", name, item[1].Type())
			}
			state.registers[index] = value
		}
		state.rsp = state.registers[4]
	}

	source, err := p.sourceFile()
	if err != nil {
		return nil, err
	}
	data, err := starfile.ReadAll(source)
	if err != nil {
		return nil, err
	}
	image, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("amd64_unwind: %w", err)
	}
	defer image.Close()
	if image.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		return nil, fmt.Errorf("amd64_unwind: PE machine %#x is not AMD64", image.Machine)
	}

	function, found, err := amd64FindRuntimeFunction(image, data, uint32(rva))
	if err != nil {
		return nil, fmt.Errorf("amd64_unwind: %w", err)
	}
	if found {
		if err := amd64ApplyUnwind(image, data, function, uint32(rva)-function.begin, &state, 0); err != nil {
			return nil, fmt.Errorf("amd64_unwind: %w", err)
		}
	}
	returnAddressAt := state.rsp
	if state.returnAt != 0 {
		returnAddressAt = state.returnAt
	}
	returnAddress, err := state.readUint64(returnAddressAt)
	if err != nil {
		return nil, fmt.Errorf("amd64_unwind: return address: %w", err)
	}
	if state.returnAt != 0 {
		state.rsp = returnAddressAt + 8
	} else {
		state.rsp += 8
	}
	state.registers[4] = state.rsp

	registers := starlark.NewDict(len(amd64RegisterNames))
	for index, name := range amd64RegisterNames {
		if err := registers.SetKey(starlark.String(name), starlark.MakeUint64(state.registers[index])); err != nil {
			return nil, err
		}
	}
	return starfile.NewRecord(starlark.StringDict{
		"function_begin":    starlark.MakeUint64(uint64(function.begin)),
		"function_end":      starlark.MakeUint64(uint64(function.end)),
		"leaf":              starlark.Bool(!found),
		"return_address":    starlark.MakeUint64(returnAddress),
		"return_address_at": starlark.MakeUint64(returnAddressAt),
		"registers":         registers,
		"stack_pointer":     starlark.MakeUint64(state.rsp),
	}), nil
}

func amd64RegisterIndex(name string) int {
	for index, candidate := range amd64RegisterNames {
		if name == candidate {
			return index
		}
	}
	return -1
}

func amd64FindRuntimeFunction(image *pe.File, data []byte, rva uint32) (amd64RuntimeFunction, bool, error) {
	optional, ok := image.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || optional.NumberOfRvaAndSizes <= pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION {
		return amd64RuntimeFunction{}, false, nil
	}
	directory := optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION]
	if directory.VirtualAddress == 0 || directory.Size < 12 {
		return amd64RuntimeFunction{}, false, nil
	}
	entries, err := amd64RVABytes(image, data, directory.VirtualAddress, directory.Size)
	if err != nil {
		return amd64RuntimeFunction{}, false, fmt.Errorf("exception directory: %w", err)
	}
	count := len(entries) / 12
	low, high := 0, count
	for low < high {
		middle := low + (high-low)/2
		entry := entries[middle*12 : middle*12+12]
		begin := binary.LittleEndian.Uint32(entry[0:4])
		if begin <= rva {
			low = middle + 1
		} else {
			high = middle
		}
	}
	if low == 0 {
		return amd64RuntimeFunction{}, false, nil
	}
	entry := entries[(low-1)*12 : (low-1)*12+12]
	function := amd64RuntimeFunction{
		begin:  binary.LittleEndian.Uint32(entry[0:4]),
		end:    binary.LittleEndian.Uint32(entry[4:8]),
		unwind: binary.LittleEndian.Uint32(entry[8:12]),
	}
	if rva < function.begin || rva >= function.end {
		return amd64RuntimeFunction{}, false, nil
	}
	return function, true, nil
}

func amd64ApplyUnwind(image *pe.File, data []byte, function amd64RuntimeFunction, controlOffset uint32, state *amd64UnwindState, depth int) error {
	if depth > 32 {
		return fmt.Errorf("chained unwind information exceeds 32 entries")
	}
	header, err := amd64RVABytes(image, data, function.unwind, 4)
	if err != nil {
		return fmt.Errorf("read unwind header at %#x: %w", function.unwind, err)
	}
	version, flags := header[0]&7, header[0]>>3
	if version != 1 && version != 2 {
		return fmt.Errorf("unsupported unwind version %d at %#x", version, function.unwind)
	}
	prologSize, codeCount := uint32(header[1]), int(header[2])
	if codeCount > amd64MaximumUnwindCodes {
		return fmt.Errorf("unwind code count %d exceeds limit", codeCount)
	}
	codes, err := amd64RVABytes(image, data, function.unwind+4, uint32(codeCount*2))
	if err != nil {
		return fmt.Errorf("read unwind codes at %#x: %w", function.unwind, err)
	}
	frameRegister := int(header[3] & 15)
	frameOffset := uint64(header[3]>>4) * 16
	activeOffset := controlOffset
	if activeOffset > prologSize {
		activeOffset = prologSize
	}
	for slot := 0; slot < codeCount; {
		codeOffset := uint32(codes[slot*2])
		operation := int(codes[slot*2+1] & 15)
		info := int(codes[slot*2+1] >> 4)
		operandSlots := 0
		switch operation {
		case amd64UnwindAllocLarge:
			if info == 0 {
				operandSlots = 1
			} else if info == 1 {
				operandSlots = 2
			} else {
				return fmt.Errorf("invalid UWOP_ALLOC_LARGE info %d", info)
			}
		case amd64UnwindSaveNonvol, amd64UnwindSaveXMM128:
			operandSlots = 1
		case amd64UnwindSaveNonvolFar, amd64UnwindSaveXMM128Far:
			operandSlots = 2
		}
		if slot+operandSlots >= codeCount {
			return fmt.Errorf("truncated unwind operation %d at slot %d", operation, slot)
		}
		if codeOffset <= activeOffset {
			u16 := func(relative int) uint64 {
				return uint64(binary.LittleEndian.Uint16(codes[(slot+relative)*2 : (slot+relative)*2+2]))
			}
			u32 := func(relative int) uint64 {
				return uint64(binary.LittleEndian.Uint32(codes[(slot+relative)*2 : (slot+relative)*2+4]))
			}
			switch operation {
			case amd64UnwindPushNonvol:
				value, err := state.readUint64(state.rsp)
				if err != nil {
					return err
				}
				state.registers[info] = value
				state.rsp += 8
			case amd64UnwindAllocLarge:
				if info == 0 {
					state.rsp += u16(1) * 8
				} else {
					state.rsp += u32(1)
				}
			case amd64UnwindAllocSmall:
				state.rsp += uint64(info)*8 + 8
			case amd64UnwindSetFPReg:
				if frameRegister == 0 {
					return fmt.Errorf("UWOP_SET_FPREG has no frame register")
				}
				state.rsp = state.registers[frameRegister] - frameOffset
			case amd64UnwindSaveNonvol:
				value, err := state.readUint64(state.rsp + u16(1)*8)
				if err != nil {
					return err
				}
				state.registers[info] = value
			case amd64UnwindSaveNonvolFar:
				value, err := state.readUint64(state.rsp + u32(1))
				if err != nil {
					return err
				}
				state.registers[info] = value
			case amd64UnwindSaveXMM128, amd64UnwindSaveXMM128Far:
				// XMM restoration does not affect control-flow unwinding.
			case amd64UnwindPushMachFrame:
				if info > 1 {
					return fmt.Errorf("invalid UWOP_PUSH_MACHFRAME info %d", info)
				}
				state.returnAt = state.rsp + uint64(info)*8
				state.rsp += 40 + uint64(info)*8
			default:
				return fmt.Errorf("unsupported unwind operation %d", operation)
			}
		}
		slot += 1 + operandSlots
	}
	state.registers[4] = state.rsp
	if flags&amd64UnwindChainInfo != 0 {
		alignedCodes := (codeCount + 1) &^ 1
		raw, err := amd64RVABytes(image, data, function.unwind+4+uint32(alignedCodes*2), 12)
		if err != nil {
			return fmt.Errorf("read chained runtime function: %w", err)
		}
		chained := amd64RuntimeFunction{
			begin:  binary.LittleEndian.Uint32(raw[0:4]),
			end:    binary.LittleEndian.Uint32(raw[4:8]),
			unwind: binary.LittleEndian.Uint32(raw[8:12]),
		}
		return amd64ApplyUnwind(image, data, chained, ^uint32(0), state, depth+1)
	}
	return nil
}

func amd64RVABytes(image *pe.File, data []byte, rva, size uint32) ([]byte, error) {
	offset, err := peRVAOffset(image, rva)
	if err != nil {
		return nil, err
	}
	end := uint64(offset) + uint64(size)
	if end < uint64(offset) || end > uint64(len(data)) {
		return nil, fmt.Errorf("RVA %#x+%#x is outside the PE file", rva, size)
	}
	return data[offset:uint32(end)], nil
}

func (state *amd64UnwindState) readUint64(address uint64) (uint64, error) {
	if address < state.stackBase || address > state.stackEnd || state.stackEnd-address < 8 {
		return 0, fmt.Errorf("stack address %#x is outside %#x..%#x", address, state.stackBase, state.stackEnd)
	}
	offset := address - state.stackBase
	return binary.LittleEndian.Uint64(state.stack[offset : offset+8]), nil
}
