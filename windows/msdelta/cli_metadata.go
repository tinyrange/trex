package msdelta

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

// ECMA-335 II.22/II.24.2: column kinds below 64 are table indexes;
// 64..76 are coded indexes. The remaining kinds have explicit widths.
const (
	cliTypeDefOrRef = 64 + iota
	cliHasConstant
	cliHasCustomAttribute
	cliHasFieldMarshal
	cliHasDeclSecurity
	cliMemberRefParent
	cliHasSemantics
	cliMethodDefOrRef
	cliMemberForwarded
	cliImplementation
	cliCustomAttributeType
	cliResolutionScope
	cliTypeOrMethodDef
	cliU16
	cliU32
	cliRVA
	cliStrings
	cliGUID
	cliBlob
)

var cliCodedTables = [...][]int{
	{2, 1, 27}, {4, 8, 23}, {6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43},
	{4, 8}, {2, 6, 32}, {2, 1, 26, 6, 27}, {20, 23}, {6, 10}, {4, 6}, {38, 35, 39},
	{-1, -1, 6, 10, -1}, {0, 26, 35, 1}, {2, 6},
}

var cliColumns = [45][]int{
	0: {cliU16, cliStrings, cliGUID, cliGUID, cliGUID},
	1: {cliResolutionScope, cliStrings, cliStrings},
	2: {cliU32, cliStrings, cliStrings, cliTypeDefOrRef, 4, 6},
	3: {4}, 4: {cliU16, cliStrings, cliBlob}, 5: {6},
	6: {cliRVA, cliU16, cliU16, cliStrings, cliBlob, 8}, 7: {8},
	8: {cliU16, cliU16, cliStrings}, 9: {2, cliTypeDefOrRef},
	10: {cliMemberRefParent, cliStrings, cliBlob},
	11: {cliU16, cliHasConstant, cliBlob},
	12: {cliHasCustomAttribute, cliCustomAttributeType, cliBlob},
	13: {cliHasFieldMarshal, cliBlob}, 14: {cliU16, cliHasDeclSecurity, cliBlob},
	15: {cliU16, cliU32, 2}, 16: {cliU32, 4}, 17: {cliBlob},
	18: {2, 20}, 19: {20}, 20: {cliU16, cliStrings, cliTypeDefOrRef},
	21: {2, 23}, 22: {23}, 23: {cliU16, cliStrings, cliBlob},
	24: {cliU16, 6, cliHasSemantics}, 25: {2, cliMethodDefOrRef, cliMethodDefOrRef},
	26: {cliStrings}, 27: {cliBlob}, 28: {cliU16, cliMemberForwarded, cliStrings, 26},
	29: {cliRVA, 4}, 30: {cliU32, cliU32}, 31: {cliU32},
	32: {cliU32, cliU16, cliU16, cliU16, cliU16, cliU32, cliBlob, cliStrings, cliStrings},
	33: {cliU32}, 34: {cliU32, cliU32, cliU32},
	35: {cliU16, cliU16, cliU16, cliU16, cliU32, cliBlob, cliStrings, cliStrings, cliBlob},
	36: {cliU32, 35}, 37: {cliU32, cliU32, cliU32, 35},
	38: {cliU32, cliStrings, cliBlob}, 39: {cliU32, cliU32, cliStrings, cliStrings, cliImplementation},
	40: {cliU32, cliU32, cliStrings, cliImplementation}, 41: {2, 2},
	42: {cliU16, cliU16, cliTypeOrMethodDef, cliStrings},
	43: {cliMethodDefOrRef, cliBlob}, 44: {42, cliTypeDefOrRef},
}

type cliMetadata struct {
	*CLIPreprocessInfo
	rowSizes     [64]int
	tableOffsets [64]int
}

// Legacy MSDelta CLI normalization uses the v1.1 GenericParam schema,
// including its trailing TypeDefOrRef Kind column. CLI4 uses four columns.
var legacyGenericParamColumns = []int{cliU16, cliU16, cliTypeOrMethodDef, cliStrings, cliTypeDefOrRef}

func (m *CLIPreprocessInfo) columns(table int) []int {
	if table == 42 && m.legacyGenericParam {
		return legacyGenericParamColumns
	}
	return cliColumns[table]
}

func (m *CLIPreprocessInfo) columnWidth(kind int) int {
	switch kind {
	case cliU16:
		return 2
	case cliU32, cliRVA:
		return 4
	case cliStrings:
		return int(m.HeapWidths[0])
	case cliGUID:
		return int(m.HeapWidths[1])
	case cliBlob:
		return int(m.HeapWidths[2])
	}
	if kind < 64 {
		if m.Rows[kind] >= 65536 {
			return 4
		}
		return 2
	}
	tables := cliCodedTables[kind-64]
	tagBits := bits.Len(uint(len(tables) - 1))
	for _, id := range tables {
		if id >= 0 && m.Rows[id] >= uint32(1)<<(16-tagBits) {
			return 4
		}
	}
	return 2
}

func layoutCLIMetadata(m *CLIPreprocessInfo) (*cliMetadata, error) {
	endMetadata := uint64(m.MetadataOffset) + uint64(m.MetadataSize)
	if !m.MetadataPresent || endMetadata > 1<<32 {
		return nil, errors.New("msdelta: invalid CLI metadata extent")
	}
	for _, stream := range m.Streams {
		if stream.Size == 0 {
			continue
		}
		if stream.Offset < m.MetadataOffset || uint64(stream.Offset)+uint64(stream.Size) > endMetadata {
			return nil, errors.New("msdelta: CLI stream exceeds metadata extent")
		}
	}
	for _, width := range m.HeapWidths {
		if width != 2 && width != 4 {
			return nil, errors.New("msdelta: invalid CLI heap index width")
		}
	}
	result := &cliMetadata{CLIPreprocessInfo: m}
	stream := m.Streams[4]
	offset := uint64(stream.Offset) + 24 + uint64(bits.OnesCount64(m.ValidTables))*4
	end := uint64(stream.Offset) + uint64(stream.Size)
	if offset > end {
		return nil, errors.New("msdelta: truncated CLI tables header")
	}
	for id, count := range m.Rows {
		if m.ValidTables&(uint64(1)<<id) == 0 {
			continue
		}
		if id >= len(cliColumns) {
			return nil, fmt.Errorf("msdelta: unknown CLI table %#x", id)
		}
		size := 0
		for _, kind := range m.columns(id) {
			size += m.columnWidth(kind)
		}
		result.rowSizes[id], result.tableOffsets[id] = size, int(offset)
		offset += uint64(count) * uint64(size)
		if offset > end {
			return nil, fmt.Errorf("msdelta: CLI table %#x exceeds stream", id)
		}
	}
	return result, nil
}

func parseCLIMetadata(data []byte, pe peLayout) (*cliMetadata, error) {
	clr := pe.directories[14]
	cor, ok := pe.rawOffset(clr.rva)
	if clr.rva == 0 || !ok || cor < 0 || cor+24 > len(data) {
		return nil, errors.New("msdelta: missing CLI header")
	}
	rva, size := get32(data, cor+8), get32(data, cor+12)
	root, ok := pe.rawOffset(rva)
	if !ok || root < 0 || uint64(root)+uint64(size) > uint64(len(data)) || size < 20 {
		return nil, errors.New("msdelta: invalid CLI metadata extent")
	}
	b := data[root : root+int(size)]
	if string(b[:4]) != "BSJB" {
		return nil, errors.New("msdelta: invalid CLI metadata signature")
	}
	versionSize := uint64(get32(b, 12))
	p := (16 + versionSize + 3) &^ 3
	if p+4 > uint64(len(b)) {
		return nil, errors.New("msdelta: truncated CLI version")
	}
	count := uint32(binary.LittleEndian.Uint16(b[p+2:]))
	p += 4
	m := &CLIPreprocessInfo{MetadataPresent: true, MetadataOffset: uint32(root), MetadataSize: size, MetadataRVA: rva, StreamCount: count}
	names := map[string]bool{}
	for range count {
		if p+8 > uint64(len(b)) {
			return nil, errors.New("msdelta: truncated CLI stream header")
		}
		off, n := get32(b, int(p)), get32(b, int(p)+4)
		nameStart := p + 8
		terminator := bytes.IndexByte(b[nameStart:min(nameStart+32, uint64(len(b)))], 0)
		if terminator < 0 {
			return nil, errors.New("msdelta: unterminated CLI stream name")
		}
		name := string(b[nameStart : nameStart+uint64(terminator)])
		if names[name] {
			return nil, errors.New("msdelta: duplicate CLI stream")
		}
		names[name] = true
		if uint64(off)+uint64(n) > uint64(size) {
			return nil, errors.New("msdelta: CLI stream exceeds metadata")
		}
		for i, want := range []string{"#Strings", "#US", "#Blob", "#GUID", "#~"} {
			if name == want || (i == 4 && name == "#-") {
				m.Streams[i] = CLIStreamInfo{Offset: uint32(root) + off, Size: n}
			}
		}
		p = (nameStart + uint64(terminator) + 4) &^ 3
	}
	m.StreamHeadersEnd = uint32(root) + uint32(p)
	t := m.Streams[4]
	if t.Size < 24 {
		return nil, errors.New("msdelta: missing CLI tables stream")
	}
	table := data[t.Offset : t.Offset+t.Size]
	for i := range m.HeapWidths {
		m.HeapWidths[i] = 2
		if table[6]&(1<<i) != 0 {
			m.HeapWidths[i] = 4
		}
	}
	if table[6]&0x40 != 0 {
		return nil, errors.New("msdelta: CLI tables extra-data header unsupported")
	}
	m.ValidTables = get64(table, 8)
	cursor := 24
	for id := range m.Rows {
		if m.ValidTables&(uint64(1)<<id) == 0 {
			continue
		}
		if cursor+4 > len(table) {
			return nil, errors.New("msdelta: truncated CLI row counts")
		}
		m.Rows[id] = get32(table, cursor)
		cursor += 4
	}
	return layoutCLIMetadata(m)
}
