// Package pe parses Portable Executable metadata without loading or executing
// the image.
package pe

import (
	"bytes"
	debugpe "debug/pe"
	"encoding/binary"
	"fmt"
)

type Export struct {
	Name      string
	Ordinal   uint32
	RVA       uint32
	Forwarder string
}

func Exports(data []byte) ([]Export, error) {
	file, err := debugpe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	exportRVA, exportSize, err := dataDirectory(file, debugpe.IMAGE_DIRECTORY_ENTRY_EXPORT)
	if err != nil {
		return nil, fmt.Errorf("pe exports: %w", err)
	}
	if exportRVA == 0 || exportSize == 0 {
		return nil, nil
	}
	exportOffset, err := rvaOffset(file, exportRVA)
	if err != nil || uint64(exportOffset)+40 > uint64(len(data)) {
		return nil, fmt.Errorf("pe exports: export directory outside file")
	}
	base := binary.LittleEndian.Uint32(data[exportOffset+16 : exportOffset+20])
	functionCount := binary.LittleEndian.Uint32(data[exportOffset+20 : exportOffset+24])
	nameCount := binary.LittleEndian.Uint32(data[exportOffset+24 : exportOffset+28])
	functionsRVA := binary.LittleEndian.Uint32(data[exportOffset+28 : exportOffset+32])
	namesRVA := binary.LittleEndian.Uint32(data[exportOffset+32 : exportOffset+36])
	ordinalsRVA := binary.LittleEndian.Uint32(data[exportOffset+36 : exportOffset+40])
	if functionCount == 0 {
		return nil, nil
	}
	functionsOffset, err := rvaOffset(file, functionsRVA)
	if err != nil || uint64(functionsOffset)+uint64(functionCount)*4 > uint64(len(data)) {
		return nil, fmt.Errorf("pe exports: export address table outside file")
	}
	names := make(map[uint32]string)
	if nameCount != 0 {
		namesOffset, namesErr := rvaOffset(file, namesRVA)
		ordinalsOffset, ordinalsErr := rvaOffset(file, ordinalsRVA)
		if namesErr != nil || ordinalsErr != nil || uint64(namesOffset)+uint64(nameCount)*4 > uint64(len(data)) || uint64(ordinalsOffset)+uint64(nameCount)*2 > uint64(len(data)) {
			return nil, fmt.Errorf("pe exports: export name table outside file")
		}
		for index := uint32(0); index < nameCount; index++ {
			nameRVA := binary.LittleEndian.Uint32(data[namesOffset+index*4:])
			name, err := cString(data, file, nameRVA)
			if err != nil {
				return nil, fmt.Errorf("pe exports: export name: %w", err)
			}
			ordinalIndex := uint32(binary.LittleEndian.Uint16(data[ordinalsOffset+index*2:]))
			names[ordinalIndex] = name
		}
	}
	result := make([]Export, 0, functionCount)
	for index := uint32(0); index < functionCount; index++ {
		rva := binary.LittleEndian.Uint32(data[functionsOffset+index*4:])
		if rva == 0 {
			continue
		}
		export := Export{Name: names[index], Ordinal: base + index, RVA: rva}
		if rva >= exportRVA && uint64(rva) < uint64(exportRVA)+uint64(exportSize) {
			export.Forwarder, err = cString(data, file, rva)
			if err != nil {
				return nil, fmt.Errorf("pe exports: forwarder: %w", err)
			}
		}
		result = append(result, export)
	}
	return result, nil
}

func dataDirectory(file *debugpe.File, index int) (uint32, uint32, error) {
	switch optional := file.OptionalHeader.(type) {
	case *debugpe.OptionalHeader32:
		if index >= len(optional.DataDirectory) {
			return 0, 0, fmt.Errorf("data directory %d unavailable", index)
		}
		return optional.DataDirectory[index].VirtualAddress, optional.DataDirectory[index].Size, nil
	case *debugpe.OptionalHeader64:
		if index >= len(optional.DataDirectory) {
			return 0, 0, fmt.Errorf("data directory %d unavailable", index)
		}
		return optional.DataDirectory[index].VirtualAddress, optional.DataDirectory[index].Size, nil
	default:
		return 0, 0, fmt.Errorf("unsupported optional header")
	}
}

func rvaOffset(file *debugpe.File, rva uint32) (uint32, error) {
	for _, section := range file.Sections {
		size := section.VirtualSize
		if section.Size > size {
			size = section.Size
		}
		if rva >= section.VirtualAddress && uint64(rva) < uint64(section.VirtualAddress)+uint64(size) {
			return section.Offset + rva - section.VirtualAddress, nil
		}
	}
	return 0, fmt.Errorf("RVA %#x is outside sections", rva)
}

func cString(data []byte, file *debugpe.File, rva uint32) (string, error) {
	offset, err := rvaOffset(file, rva)
	if err != nil || offset >= uint32(len(data)) {
		return "", fmt.Errorf("string RVA %#x outside file", rva)
	}
	end := bytes.IndexByte(data[offset:], 0)
	if end < 0 {
		return "", fmt.Errorf("unterminated string at RVA %#x", rva)
	}
	return string(data[offset : offset+uint32(end)]), nil
}
