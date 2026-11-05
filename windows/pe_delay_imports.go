package windows

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func peDelayImportsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("pe.delay_imports", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pe.delay_imports: expected file")
	}
	data, err := peReadSnapshotData(file)
	if err != nil {
		return nil, err
	}
	imports, err := peDelayImports(data)
	if err != nil {
		return nil, fmt.Errorf("pe.delay_imports: %w", err)
	}
	return peImportsValue(imports)
}

// Delay descriptors use 32-bit address fields even in PE32+. Bit 0 selects
// RVAs; older descriptors and their named thunks use preferred-image VAs.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#delay-load-import-tables-image-only
func peDelayImports(data []byte) ([]peImport, error) {
	image, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer image.Close()
	rva, size, is64, err := peDataDirectory(image, 13)
	if err != nil {
		return nil, err
	}
	if rva == 0 && size == 0 {
		return nil, nil
	}
	if rva == 0 || size < 32 {
		return nil, fmt.Errorf("invalid delay directory")
	}
	var base uint64
	var headers uint32
	switch h := image.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		base, headers = uint64(h.ImageBase), h.SizeOfHeaders
	case *pe.OptionalHeader64:
		base, headers = h.ImageBase, h.SizeOfHeaders
	}
	// Return only file-backed bytes. A virtual zero-fill tail must not alias
	// unrelated raw data from the following section.
	span := func(address uint64) ([]byte, error) {
		if address > 0xffffffff {
			return nil, fmt.Errorf("RVA overflow")
		}
		start, end := uint64(0), uint64(0)
		if address < uint64(headers) {
			start, end = address, uint64(headers)
		} else {
			for _, section := range image.Sections {
				if address >= uint64(section.VirtualAddress) && address-uint64(section.VirtualAddress) < uint64(section.Size) {
					start = uint64(section.Offset) + address - uint64(section.VirtualAddress)
					end = uint64(section.Offset) + uint64(section.Size)
					break
				}
			}
		}
		if end == 0 || start >= end || end > uint64(len(data)) {
			return nil, fmt.Errorf("RVA %#x outside file-backed image", address)
		}
		if end-start > 1<<32-address {
			end = start + (1<<32 - address)
		}
		return data[start:end], nil
	}
	read := func(address uint64, count uint64) ([]byte, error) {
		value, err := span(address)
		if err != nil {
			return nil, err
		}
		if count > uint64(len(value)) || address+count > 1<<32 {
			return nil, fmt.Errorf("truncated delay import at RVA %#x", address)
		}
		return value[:count], nil
	}
	text := func(address uint32) (string, error) {
		value, err := span(uint64(address))
		if err != nil {
			return "", err
		}
		end := bytes.IndexByte(value, 0)
		if end <= 0 {
			return "", fmt.Errorf("empty or unterminated import name")
		}
		return string(value[:end]), nil
	}
	width, ordinalFlag := uint64(4), uint64(1<<31)
	if is64 {
		width, ordinalFlag = 8, 1<<63
	}
	var result []peImport
	for offset := uint64(0); offset+32 <= uint64(size); offset += 32 {
		d, err := read(uint64(rva)+offset, 32)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(d, make([]byte, 32)) {
			return result, nil
		}
		attributes := binary.LittleEndian.Uint32(d)
		if attributes & ^uint32(1) != 0 {
			return nil, fmt.Errorf("reserved delay descriptor attributes %#x", attributes)
		}
		address := func(value uint64) (uint32, error) {
			if attributes&1 == 0 {
				if value < base {
					return 0, fmt.Errorf("delay import VA below image base")
				}
				value -= base
			}
			if value == 0 || value > 0xffffffff {
				return 0, fmt.Errorf("invalid delay import address")
			}
			return uint32(value), nil
		}
		var fields [3]uint32
		for i, field := range []int{4, 12, 16} {
			fields[i], err = address(uint64(binary.LittleEndian.Uint32(d[field:])))
			if err != nil {
				return nil, err
			}
		}
		dll, err := text(fields[0])
		if err != nil {
			return nil, err
		}
		for index := uint64(0); ; index++ {
			table, iat := uint64(fields[2])+index*width, uint64(fields[1])+index*width
			value, err := read(table, width)
			if err != nil {
				return nil, err
			}
			if _, err = read(iat, width); err != nil {
				return nil, err
			}
			thunk := uint64(binary.LittleEndian.Uint32(value))
			if is64 {
				thunk = binary.LittleEndian.Uint64(value)
			}
			if thunk == 0 {
				break
			}
			imp := peImport{dll: dll, descriptor: int(offset / 32), originalFirstThunk: fields[2], firstThunk: fields[1], tableRVA: uint32(table), iatRVA: uint32(iat)}
			if thunk&ordinalFlag != 0 {
				if thunk & ^(ordinalFlag|0xffff) != 0 {
					return nil, fmt.Errorf("invalid delay ordinal")
				}
				imp.ordinal = uint16(thunk)
			} else {
				name, err := address(thunk)
				if err != nil {
					return nil, err
				}
				hint, err := read(uint64(name), 2)
				if err != nil || name > 0xfffffffd {
					return nil, fmt.Errorf("invalid delay hint/name address")
				}
				imp.hint = binary.LittleEndian.Uint16(hint)
				imp.name, err = text(name + 2)
				if err != nil {
					return nil, err
				}
			}
			result = append(result, imp)
		}
	}
	return nil, fmt.Errorf("unterminated delay descriptor table")
}
