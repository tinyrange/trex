package peimage

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
)

// RuntimeFunction and UnwindInfo describe the PE AMD64 exception directory.
// All addresses remain image-relative and no host loader state is involved.
// Format: https://learn.microsoft.com/cpp/build/exception-handling-x64
type RuntimeFunction struct{ Begin, End, Unwind uint32 }
type UnwindInfo struct {
	Function                                      RuntimeFunction
	Flags, PrologSize, FrameRegister, FrameOffset byte
	Codes                                         []byte
	Handler, HandlerData                          uint32
	Chained                                       *RuntimeFunction
}

func (i *Image) unwindBytes(rva, size uint64) ([]byte, error) {
	if rva > uint64(len(i.Data)) || size > uint64(len(i.Data))-rva {
		return nil, fmt.Errorf("PE unwind range exceeds image")
	}
	return i.Data[rva : rva+size], nil
}

func (i *Image) runtimeFunction(data []byte) (RuntimeFunction, error) {
	f := RuntimeFunction{binary.LittleEndian.Uint32(data), binary.LittleEndian.Uint32(data[4:]), binary.LittleEndian.Uint32(data[8:])}
	if f.Begin >= f.End || uint64(f.End) > uint64(len(i.Data)) || f.Unwind%4 != 0 || uint64(f.Unwind)+4 > uint64(len(i.Data)) {
		return f, fmt.Errorf("PE invalid AMD64 runtime function")
	}
	return f, nil
}

// AMD64UnwindInfo looks up a function and parses version-one UNWIND_INFO.
// A nil result denotes a leaf function with no exception-directory entry.
func (i *Image) AMD64UnwindInfo(rva uint32) (*UnwindInfo, error) {
	if i.Architecture.Name != "amd64" {
		return nil, fmt.Errorf("PE unwind lookup requires AMD64")
	}
	directory := i.Directories[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION]
	if directory.Size == 0 {
		return nil, nil
	}
	if directory.VirtualAddress%4 != 0 || directory.Size%12 != 0 {
		return nil, fmt.Errorf("PE malformed AMD64 exception directory")
	}
	data, err := i.unwindBytes(uint64(directory.VirtualAddress), uint64(directory.Size))
	if err != nil {
		return nil, err
	}
	var selected *RuntimeFunction
	var previousEnd uint32
	for offset := 0; offset < len(data); offset += 12 {
		function, err := i.runtimeFunction(data[offset:])
		if err != nil {
			return nil, err
		}
		if offset != 0 && function.Begin < previousEnd {
			return nil, fmt.Errorf("PE unordered or overlapping runtime functions")
		}
		previousEnd = function.End
		if rva >= function.Begin && rva < function.End {
			copy := function
			selected = &copy
		}
	}
	if selected == nil {
		return nil, nil
	}
	header, err := i.unwindBytes(uint64(selected.Unwind), 4)
	if err != nil {
		return nil, err
	}
	if header[0]&7 != 1 {
		return nil, fmt.Errorf("PE unsupported AMD64 unwind version %d", header[0]&7)
	}
	info := &UnwindInfo{Function: *selected, Flags: header[0] >> 3, PrologSize: header[1], FrameRegister: header[3] & 15, FrameOffset: (header[3] >> 4) * 16}
	if info.Flags & ^byte(7) != 0 || info.Flags&4 != 0 && info.Flags&3 != 0 || info.FrameRegister == 0 && info.FrameOffset != 0 {
		return nil, fmt.Errorf("PE invalid AMD64 unwind flags/frame")
	}
	codeBytes := uint64(header[2]) * 2
	codes, err := i.unwindBytes(uint64(selected.Unwind)+4, codeBytes)
	if err != nil {
		return nil, err
	}
	info.Codes = append([]byte(nil), codes...)
	tail := uint64(selected.Unwind) + 4 + (codeBytes+3)&^uint64(3)
	if info.Flags&4 != 0 {
		data, err := i.unwindBytes(tail, 12)
		if err != nil {
			return nil, err
		}
		function, err := i.runtimeFunction(data)
		if err != nil {
			return nil, err
		}
		info.Chained = &function
	} else if info.Flags&3 != 0 {
		data, err := i.unwindBytes(tail, 4)
		if err != nil {
			return nil, err
		}
		info.Handler = binary.LittleEndian.Uint32(data)
		if info.Handler == 0 || uint64(info.Handler) >= uint64(len(i.Data)) {
			return nil, fmt.Errorf("PE unwind handler exceeds image")
		}
		info.HandlerData = uint32(tail + 4)
	}
	return info, nil
}

// CScope is one __C_specific_handler scope-table entry. Jump==0 denotes a
// termination handler; other entries describe exception filters and handlers.
type CScope struct{ Begin, End, Handler, Jump uint32 }

func (i *Image) CScopes(rva uint32) ([]CScope, error) {
	header, err := i.unwindBytes(uint64(rva), 4)
	if err != nil {
		return nil, err
	}
	count := binary.LittleEndian.Uint32(header)
	if count > 4096 {
		return nil, fmt.Errorf("PE C scope table exceeds record budget")
	}
	data, err := i.unwindBytes(uint64(rva)+4, uint64(count)*16)
	if err != nil {
		return nil, err
	}
	scopes := make([]CScope, 0, count)
	for offset := 0; offset < len(data); offset += 16 {
		entry := data[offset:]
		scope := CScope{binary.LittleEndian.Uint32(entry), binary.LittleEndian.Uint32(entry[4:]), binary.LittleEndian.Uint32(entry[8:]), binary.LittleEndian.Uint32(entry[12:])}
		if scope.Begin >= scope.End || uint64(scope.End) > uint64(len(i.Data)) || uint64(scope.Handler) >= uint64(len(i.Data)) || uint64(scope.Jump) >= uint64(len(i.Data)) || scope.Jump == 0 && scope.Handler <= 1 {
			return nil, fmt.Errorf("PE invalid C scope table entry")
		}
		scopes = append(scopes, scope)
	}
	return scopes, nil
}
