// Package pe implements portable readers for selected Portable Executable
// structures over TinyRangeX random-access byte sources.
package pe

import (
	debugpe "debug/pe"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

const resourceDirectoryIndex = 2

// OpenNumericResource returns one numeric type/name resource as a bounded
// random-access view of the original PE. Named entries are not aliases for
// numeric IDs. Multiple language leaves are accepted only when they identify
// the same byte range.
func OpenNumericResource(file storage.Reader, typeID, nameID uint32, maximumSize int64) (storage.Reader, error) {
	if file == nil || file.Size() < 0 {
		return nil, fmt.Errorf("pe resource: file is required")
	}
	if maximumSize < 0 {
		return nil, fmt.Errorf("pe resource: negative size bound")
	}
	parsed, err := debugpe.NewFile(io.NewSectionReader(file, 0, file.Size()))
	if err != nil {
		return nil, fmt.Errorf("pe resource: parse PE: %w", err)
	}
	defer parsed.Close()
	var resourceRVA, resourceSize uint32
	switch optional := parsed.OptionalHeader.(type) {
	case *debugpe.OptionalHeader32:
		if len(optional.DataDirectory) > resourceDirectoryIndex {
			resourceRVA, resourceSize = optional.DataDirectory[resourceDirectoryIndex].VirtualAddress, optional.DataDirectory[resourceDirectoryIndex].Size
		}
	case *debugpe.OptionalHeader64:
		if len(optional.DataDirectory) > resourceDirectoryIndex {
			resourceRVA, resourceSize = optional.DataDirectory[resourceDirectoryIndex].VirtualAddress, optional.DataDirectory[resourceDirectoryIndex].Size
		}
	default:
		return nil, fmt.Errorf("pe resource: unsupported optional header")
	}
	if resourceRVA == 0 || resourceSize < 16 {
		return nil, fmt.Errorf("pe resource: image has no resource directory")
	}
	resourceOffset, err := rvaOffset(parsed, resourceRVA)
	if err != nil {
		return nil, err
	}
	if uint64(resourceOffset)+uint64(resourceSize) > uint64(file.Size()) {
		return nil, fmt.Errorf("pe resource: directory exceeds file")
	}
	reader := numericResourceReader{file: file, parsed: parsed, baseRVA: resourceRVA, baseOffset: resourceOffset, directorySize: resourceSize}
	typeEntry, err := reader.numericEntry(0, typeID)
	if err != nil {
		return nil, fmt.Errorf("pe resource: type %d: %w", typeID, err)
	}
	if typeEntry&0x80000000 == 0 {
		return nil, fmt.Errorf("pe resource: type %d is not a directory", typeID)
	}
	nameEntry, err := reader.numericEntry(typeEntry&0x7fffffff, nameID)
	if err != nil {
		return nil, fmt.Errorf("pe resource: type %d name %d: %w", typeID, nameID, err)
	}
	if nameEntry&0x80000000 == 0 {
		return nil, fmt.Errorf("pe resource: type %d name %d is not a language directory", typeID, nameID)
	}
	leaves, err := reader.dataLeaves(nameEntry & 0x7fffffff)
	if err != nil {
		return nil, fmt.Errorf("pe resource: type %d name %d: %w", typeID, nameID, err)
	}
	if len(leaves) == 0 {
		return nil, fmt.Errorf("pe resource: type %d name %d has no language", typeID, nameID)
	}
	chosen := leaves[0]
	for _, leaf := range leaves[1:] {
		if leaf.offset != chosen.offset || leaf.size != chosen.size {
			return nil, fmt.Errorf("pe resource: type %d name %d has ambiguous language payloads", typeID, nameID)
		}
	}
	if int64(chosen.size) > maximumSize {
		return nil, fmt.Errorf("pe resource: payload size %d exceeds %d-byte bound", chosen.size, maximumSize)
	}
	return io.NewSectionReader(file, int64(chosen.offset), int64(chosen.size)), nil
}

type numericResourceReader struct {
	file          storage.Reader
	parsed        *debugpe.File
	baseRVA       uint32
	baseOffset    uint32
	directorySize uint32
}

type resourceLeaf struct{ offset, size uint32 }

func (reader numericResourceReader) numericEntry(directory, wanted uint32) (uint32, error) {
	entries, err := reader.entries(directory)
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		if entry.name&0x80000000 == 0 && entry.name == wanted {
			return entry.value, nil
		}
	}
	return 0, fmt.Errorf("numeric entry %d is absent", wanted)
}

type resourceEntry struct{ name, value uint32 }

func (reader numericResourceReader) entries(directory uint32) ([]resourceEntry, error) {
	if directory > reader.directorySize-16 {
		return nil, fmt.Errorf("directory offset %#x is outside resource data", directory)
	}
	header := make([]byte, 16)
	if _, err := reader.file.ReadAt(header, int64(reader.baseOffset+directory)); err != nil {
		return nil, err
	}
	count := uint32(binary.LittleEndian.Uint16(header[12:])) + uint32(binary.LittleEndian.Uint16(header[14:]))
	if count > (reader.directorySize-directory-16)/8 {
		return nil, fmt.Errorf("directory entry table exceeds resource data")
	}
	raw := make([]byte, int(count)*8)
	if _, err := reader.file.ReadAt(raw, int64(reader.baseOffset+directory+16)); err != nil {
		return nil, err
	}
	result := make([]resourceEntry, count)
	for index := range result {
		result[index] = resourceEntry{name: binary.LittleEndian.Uint32(raw[index*8:]), value: binary.LittleEndian.Uint32(raw[index*8+4:])}
	}
	return result, nil
}

func (reader numericResourceReader) dataLeaves(directory uint32) ([]resourceLeaf, error) {
	entries, err := reader.entries(directory)
	if err != nil {
		return nil, err
	}
	result := make([]resourceLeaf, 0, len(entries))
	for _, entry := range entries {
		if entry.value&0x80000000 != 0 || entry.value > reader.directorySize-16 {
			return nil, fmt.Errorf("language entry has invalid data offset %#x", entry.value)
		}
		var raw [16]byte
		if _, err := reader.file.ReadAt(raw[:], int64(reader.baseOffset+entry.value)); err != nil {
			return nil, err
		}
		rva, size := binary.LittleEndian.Uint32(raw[:4]), binary.LittleEndian.Uint32(raw[4:8])
		offset, err := rvaOffset(reader.parsed, rva)
		if err != nil {
			return nil, err
		}
		if uint64(offset)+uint64(size) > uint64(reader.file.Size()) {
			return nil, fmt.Errorf("resource payload exceeds file")
		}
		result = append(result, resourceLeaf{offset: offset, size: size})
	}
	return result, nil
}

func rvaOffset(file *debugpe.File, rva uint32) (uint32, error) {
	for _, section := range file.Sections {
		span := section.VirtualSize
		if section.Size > span {
			span = section.Size
		}
		if rva >= section.VirtualAddress && uint64(rva-section.VirtualAddress) < uint64(span) {
			offset := uint64(section.Offset) + uint64(rva-section.VirtualAddress)
			if offset > uint64(^uint32(0)) {
				break
			}
			return uint32(offset), nil
		}
	}
	return 0, fmt.Errorf("pe resource: RVA %#x is not mapped", rva)
}
