package msdelta

import "fmt"

// MARK claims the CLI method header and code, but not alignment padding or
// trailing exception sections. Like the token enumerator, it stops before the
// final MethodDef row. Unclaimed bytes remain eligible for native x86 scans.
func markCLIMethodBodies(marker, source []byte, pe peLayout, metadata *cliMetadata) error {
	for row := uint32(0); row+1 < metadata.Rows[6]; row++ {
		off := metadata.tableOffsets[6] + int(row)*metadata.rowSizes[6]
		rva := get32(source, off)
		if rva == 0 || get16(source, off+4)&3 != 0 {
			continue
		}
		start, backed := pe.rawOffset(rva)
		_, end, valid := cliMethodCode(source, pe, rva)
		if !backed || !valid || end > len(marker) {
			return fmt.Errorf("msdelta: invalid CLI method %d marking at RVA %#x", row+1, rva)
		}
		for i := start; i < end; i++ {
			marker[i] |= 3
		}
	}
	return nil
}

// CLI instruction normalization enumerates immutable MethodDef RVAs, but reads
// each body's current bytes. Native visits aliases repeatedly in row order;
// shared bodies can therefore have their tokens remapped more than once.
func transformCLIMethodTokens(dst, source []byte, pe peLayout, metadata *cliMetadata, target *CLIPreprocessInfo) error {
	if target == nil {
		return nil
	}
	remap := newCLIRemap(target)
	needed := len(target.HeapMaps[1]) != 0
	for _, entries := range target.TableMaps {
		needed = needed || len(entries) != 0
	}
	if !needed {
		return nil
	}
	// The native method-body enumerator stops before the final MethodDef
	// row. This is a row-order boundary, not the last physical code address:
	// swapping the last two source RVAs makes the formerly skipped body map.
	for row := uint32(0); row+1 < metadata.Rows[6]; row++ {
		off := metadata.tableOffsets[6] + int(row)*metadata.rowSizes[6]
		rva := get32(source, off)
		// MethodImplAttributes.CodeTypeMask: only IL has a CLI method header.
		if rva == 0 || get16(source, off+4)&3 != 0 {
			continue
		}
		start, end, ok := cliMethodCode(source, pe, rva)
		if !ok || end > len(dst) {
			return fmt.Errorf("msdelta: invalid CLI method %d body at RVA %#x", row+1, rva)
		}
		if err := transformCLIInstructions(dst[start:end], dst[start:end], &remap); err != nil {
			return fmt.Errorf("msdelta: CLI method %d: %w", row+1, err)
		}
	}
	return nil
}

// ECMA-335 II.25.4 tiny/fat headers. Limit code to the actual raw-backed
// section; virtual tails, padding and exception sections are not instructions.
func cliMethodCode(source []byte, pe peLayout, rva uint32) (start, end int, ok bool) {
	for _, section := range pe.sections {
		if rva < section.rva || uint64(rva-section.rva) >= uint64(section.rawSize) {
			continue
		}
		off := uint64(section.rawStart) + uint64(rva-section.rva)
		limit := min(uint64(len(source)), uint64(section.rawStart)+uint64(section.rawSize))
		if off >= limit {
			return 0, 0, false
		}
		var header, size uint64
		switch source[off] & 3 {
		case 2:
			header, size = 1, uint64(source[off]>>2)
		case 3:
			if limit-off < 12 {
				return 0, 0, false
			}
			header = uint64(get16(source, int(off))>>12) * 4
			size = uint64(get32(source, int(off)+4))
			if header < 12 {
				return 0, 0, false
			}
		default:
			return 0, 0, false
		}
		if header > limit-off || size > limit-off-header {
			return 0, 0, false
		}
		return int(off + header), int(off + header + size), true
	}
	return 0, 0, false
}

func (r *cliRemap) token(value uint32) uint32 {
	kind, index := value>>24, value&0xffffff
	var mapped uint32
	switch {
	case kind < 64:
		mapped = cliMapIndex(r.tables[kind], index)
	case kind == 0x70:
		mapped = cliMapIndex(r.heaps[1], index)
	default:
		return value
	}
	if mapped > 0xffffff {
		return value
	}
	return kind<<24 | mapped
}

const (
	cliOperandToken  = -1
	cliOperandSwitch = -2
)

// Operand encodings follow the public CLI instruction set. InlineSig (calli)
// is a metadata token too; branch displacements and switch tables are not.
func cliOperand(op uint16) int {
	switch {
	case op >= 0x0e && op <= 0x13, op == 0x1f, op >= 0x2b && op <= 0x37, op == 0xde, op == 0xfe12:
		return 1
	case op >= 0xfe09 && op <= 0xfe0e:
		return 2
	case op == 0x20, op == 0x22, op >= 0x38 && op <= 0x44, op == 0xdd:
		return 4
	case op == 0x21, op == 0x23:
		return 8
	case op == 0x45:
		return cliOperandSwitch
	case op >= 0x27 && op <= 0x29, op >= 0x6f && op <= 0x75, op == 0x79,
		op >= 0x7b && op <= 0x81, op == 0x8c, op == 0x8d, op == 0x8f,
		op >= 0xa3 && op <= 0xa5, op == 0xc2, op == 0xc6, op == 0xd0,
		op == 0xfe06, op == 0xfe07, op == 0xfe15, op == 0xfe16, op == 0xfe1c:
		return cliOperandToken
	default:
		return 0
	}
}

func transformCLIInstructions(dst, source []byte, remap *cliRemap) error {
	if len(dst) != len(source) {
		return fmt.Errorf("instruction buffer sizes differ")
	}
	for cursor := 0; cursor < len(source); {
		op := uint16(source[cursor])
		cursor++
		if op == 0xfe {
			if cursor == len(source) {
				return fmt.Errorf("truncated IL opcode at %d", cursor-1)
			}
			op = 0xfe00 | uint16(source[cursor])
			cursor++
		}
		width := cliOperand(op)
		switch width {
		case cliOperandToken:
			if len(source)-cursor < 4 {
				return fmt.Errorf("truncated IL token at %d", cursor)
			}
			put32(dst, cursor, remap.token(get32(source, cursor)))
			width = 4
		case cliOperandSwitch:
			if len(source)-cursor < 4 {
				return fmt.Errorf("truncated IL switch at %d", cursor)
			}
			count := uint64(get32(source, cursor))
			if count > uint64((len(source)-cursor-4)/4) {
				return fmt.Errorf("IL switch exceeds code at %d", cursor)
			}
			width = 4 + int(count)*4
		}
		if width > len(source)-cursor {
			return fmt.Errorf("truncated IL operand at %d", cursor)
		}
		cursor += width
	}
	return nil
}
