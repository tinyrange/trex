package msdelta

import (
	"bytes"
	"encoding/binary"
)

const (
	peTransformX86E8        = uint64(0x1)
	peTransformMarkCode     = uint64(0x2)
	peTransformImports      = uint64(0x4)
	peTransformExports      = uint64(0x8)
	peTransformResources    = uint64(0x10)
	peTransformRelocs       = uint64(0x20)
	peTransformJmpsX86      = uint64(0x80)
	peTransformCallsX86     = uint64(0x100)
	peTransformDisasmX64    = uint64(0x200)
	peTransformPdataX64     = uint64(0x400)
	peTransformUnbind       = uint64(0x2000)
	peTransformCLIDisasm    = uint64(0x4000)
	peTransformCLIMetadata  = uint64(0x8000)
	peTransformCLI4Metadata = uint64(0x200000)
	peTransformCLI4Disasm   = uint64(0x400000)
)

// restoreX86E8 reverses the classic whole-buffer x86 CALL transform. The
// stored operand is an absolute position in the transform window; restoration
// converts it back to a relative displacement. This transform is selected by
// the PA header rather than by the PE source-preprocessing stream.
func restoreX86E8(data []byte) {
	layout, err := parsePELayout(data)
	if err != nil || layout.machine != 0x14c || layout.imageBaseSize != 4 {
		return
	}
	// DELTA_FLAG_E8 selects target restoration independently of source CLI
	// normalization. ILONLY does not suppress it (including metadata-only PEs).
	if len(data) < 5 || uint64(len(data)) >= uint64(1)<<31 {
		return
	}
	size := int32(len(data))
	// MSDelta includes the final complete five-byte CALL. Unlike the LZX
	// archive filter, it does not reserve a ten-byte untransformed tail.
	for position := 0; position < len(data)-4; {
		if data[position] != 0xe8 {
			position++
			continue
		}
		value := int32(get32(data, position+1))
		if value >= -int32(position) && value < size {
			if value >= 0 {
				value -= int32(position)
			} else {
				value += size
			}
			put32(data, position+1, uint32(value))
		}
		position += 5
	}
}

func transformPESource(data []byte, layout peLayout, rift riftTable, flags uint64, target peRestore) {
	_ = transformPESourceTraced(data, layout, rift, flags, target, nil, nil)
}

func transformPESourceTraced(data []byte, layout peLayout, rift riftTable, flags uint64, target peRestore, trace *peTransformTrace, managed *cliMetadata) error {
	if flags&peTransformUnbind != 0 {
		unbindPE(data, layout)
	}
	put32(data, int(layout.timestampOffset), target.timestamp)
	marker := make([]byte, len(data))
	if layout.machine == 0x14c && flags&peTransformMarkCode != 0 {
		markNonExecutablePE(marker, layout)
	}
	if flags&peTransformMarkCode != 0 {
		markPEDirectories(marker, layout)
		if managed != nil {
			if err := markCLIMethodBodies(marker, data, layout, managed); err != nil {
				return err
			}
		}
	}
	if flags&peTransformImports != 0 {
		transformImports(data, layout, rift, target.imageBase, marker)
	}
	if flags&peTransformExports != 0 {
		transformExports(data, layout, rift, marker)
	}
	if flags&peTransformResources != 0 {
		transformResources(data, layout, rift, marker)
	}
	if flags&peTransformRelocs != 0 {
		transformRelocations(data, layout, rift, target.imageBase, marker)
	}
	// Managed method headers/code are claimed by MARK, not by a blanket
	// IL-only exclusion. Native scans still cover unclaimed EH data and gaps.
	nativeX86 := layout.machine == 0x14c
	if nativeX86 && flags&peTransformJmpsX86 != 0 {
		transformJmpsX86(data, layout, rift, marker)
	}
	if nativeX86 && flags&peTransformCallsX86 != 0 {
		transformCallsX86(data, layout, rift, marker)
	}
	if layout.machine == 0x8664 && flags&peTransformDisasmX64 != 0 {
		transformDisasmX64Traced(data, layout, rift, marker, trace)
	}
	if layout.machine == 0x8664 && flags&peTransformPdataX64 != 0 {
		transformPdataX64(data, layout, rift)
	}
	if layout.imageBaseSize == 4 {
		put32(data, int(layout.imageBaseOffset), uint32(target.imageBase))
	} else {
		put64(data, int(layout.imageBaseOffset), target.imageBase)
	}
	return nil
}

func unbindPE(data []byte, layout peLayout) {
	directory := layout.directories[1]
	base, ok := layout.rawOffset(directory.rva)
	if ok && directory.rva != 0 {
		pointerSize := 4
		if layout.imageBaseSize == 8 {
			pointerSize = 8
		}
		for index := 0; index < 4096; index++ {
			offset := base + index*20
			if offset+20 > len(data) {
				break
			}
			oft, timestamp, name, ft := get32(data, offset), get32(data, offset+4), get32(data, offset+12), get32(data, offset+16)
			if oft == 0 && name == 0 && ft == 0 {
				break
			}
			if timestamp == 0 {
				continue
			}
			put32(data, offset+4, 0)
			put32(data, offset+8, 0)
			source, sourceOK := layout.rawOffset(oft)
			target, targetOK := layout.rawOffset(ft)
			if !sourceOK || !targetOK {
				continue
			}
			for slot := 0; ; slot++ {
				s, d := source+slot*pointerSize, target+slot*pointerSize
				if s+pointerSize > len(data) || d+pointerSize > len(data) {
					break
				}
				if (pointerSize == 8 && get64(data, s) == 0) || (pointerSize == 4 && get32(data, s) == 0) {
					break
				}
				copy(data[d:d+pointerSize], data[s:s+pointerSize])
			}
		}
	}
	for _, section := range layout.sections {
		if section.name == [8]byte{'.', 'i', 'd', 'a', 't', 'a'} {
			put32(data, int(section.rawPointerOffset)+16, section.characteristics|0xc0000000)
		}
	}
}

func transformImports(data []byte, layout peLayout, rift riftTable, targetBase uint64, marker []byte) {
	directory := layout.directories[1]
	base, ok := layout.rawOffset(directory.rva)
	if !ok || directory.rva == 0 {
		return
	}
	pointerSize := 4
	ordinal := uint64(1 << 31)
	if layout.imageBaseSize == 8 {
		pointerSize, ordinal = 8, uint64(1)<<63
	}
	for index := 0; index < 4096; index++ {
		offset := base + index*20
		if offset+20 > len(data) {
			break
		}
		oft, timestamp, name, ft := get32(data, offset), get32(data, offset+4), get32(data, offset+12), get32(data, offset+16)
		if oft == 0 && name == 0 && ft == 0 {
			break
		}
		walkImportThunks(data, layout, rift, oft, false, true, pointerSize, ordinal, targetBase, marker)
		walkImportThunks(data, layout, rift, ft, timestamp != 0, false, pointerSize, ordinal, targetBase, marker)
		mapRVA32(data, offset, rift)
		markPEBytes(marker, offset, 4)
		mapRVA32(data, offset+12, rift)
		markPEBytes(marker, offset+12, 4)
		mapRVA32(data, offset+16, rift)
		markPEBytes(marker, offset+16, 4)
	}
}

func walkImportThunks(data []byte, layout peLayout, rift riftTable, rva uint32, bound, lookup bool, size int, ordinal, targetBase uint64, marker []byte) {
	base, ok := layout.rawOffset(rva)
	if !ok || rva == 0 {
		return
	}
	skipNames := false
	for index := 0; ; index++ {
		offset := base + index*size
		if offset+size > len(data) {
			break
		}
		value := uint64(get32(data, offset))
		if size == 8 {
			value = get64(data, offset)
		}
		if value == 0 {
			break
		}
		// The first entry classifies an original lookup table. An ordinal-led
		// table remains in source coordinates, including any later named imports.
		// A name-led lookup and the parallel IAT can mix both forms; their ordinal
		// entries are skipped while later named entries continue to be mapped.
		if index == 0 && lookup && value&ordinal != 0 {
			skipNames = true
		}
		if !bound && value&ordinal != 0 {
			markPEBytes(marker, offset, size)
			continue
		}
		// A PE32+ name thunk holds a 32-bit RVA. Zero-timestamp IATs may
		// instead contain image VAs (win32kbase.sys); leave those for the
		// relocation pass rather than rewriting their low word as an RVA.
		if !bound && size == 8 && value>>32 != 0 {
			markPEBytes(marker, offset, size)
			continue
		}
		if bound {
			relative := int64(value) - int64(layout.imageBase)
			mapped := uint64(int64(targetBase) + rift.mapForward(relative))
			if size == 8 {
				put64(data, offset, mapped)
			} else {
				put32(data, offset, uint32(mapped))
			}
		} else if !skipNames {
			// IMPORTS owns the complete IMAGE_IMPORT_BY_NAME, including its
			// hint and terminating NUL (but not alignment padding). Bit 2
			// prevents the later unlisted-pointer scan from interpreting
			// unaligned ASCII suffixes as image addresses.
			if name, ok := layout.rawOffset(uint32(value)); ok && name >= 0 && name+2 <= len(data) {
				if length := bytes.IndexByte(data[name+2:], 0); length >= 0 {
					for i := name; i < name+2+length+1; i++ {
						marker[i] |= 3
					}
				}
			}
			put32(data, offset, uint32(rift.mapForward(int64(uint32(value)))))
		}
		markPEBytes(marker, offset, size)
	}
}

func transformExports(data []byte, layout peLayout, rift riftTable, marker []byte) {
	directory := layout.directories[0]
	base, ok := layout.rawOffset(directory.rva)
	if !ok || directory.rva == 0 || base+40 > len(data) {
		return
	}
	for _, pair := range [][2]uint32{{get32(data, base+28), get32(data, base+20)}, {get32(data, base+32), get32(data, base+24)}} {
		array, ok := layout.rawOffset(pair[0])
		if !ok {
			continue
		}
		count := min(uint64(pair[1]), uint64(len(data)-array)/4)
		for index := range int(count) {
			mapRVA32(data, array+index*4, rift)
			markPEBytes(marker, array+index*4, 4)
		}
	}
	for _, offset := range []int{12, 28, 32, 36} {
		mapRVA32(data, base+offset, rift)
		markPEBytes(marker, base+offset, 4)
	}
}

func transformResources(data []byte, layout peLayout, rift riftTable, marker []byte) {
	directory := layout.directories[2]
	base, ok := layout.rawOffset(directory.rva)
	if !ok || directory.rva == 0 {
		return
	}
	end := min(len(data), base+int(directory.size))
	baseMapped := rift.mapForward(int64(directory.rva))
	remapRelative := func(value uint32) uint32 {
		return uint32(rift.mapForward(int64(directory.rva)+int64(value)) - baseMapped)
	}
	stack := []int{base}
	visited := map[int]bool{}
	for len(stack) != 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited[dir] || dir < base || dir+16 > end {
			continue
		}
		visited[dir] = true
		count := int(get16(data, dir+12)) + int(get16(data, dir+14))
		count = min(count, (end-dir-16)/8)
		for index := range count {
			offset := dir + 16 + index*8
			name, entry := get32(data, offset), get32(data, offset+4)
			if name&0x80000000 != 0 {
				put32(data, offset, 0x80000000|(remapRelative(name&0x7fffffff)&0x7fffffff))
				markPEBytes(marker, offset, 4)
			}
			if entry&0x80000000 != 0 {
				child := base + int(entry&0x7fffffff)
				if child > offset && child+16 <= end {
					stack = append(stack, child)
				}
				put32(data, offset+4, 0x80000000|(remapRelative(entry&0x7fffffff)&0x7fffffff))
				markPEBytes(marker, offset+4, 4)
			} else {
				leaf := base + int(entry&0x7fffffff)
				if leaf >= base && leaf+16 <= end {
					put32(data, leaf, remapRelative(get32(data, leaf)))
					markPEBytes(marker, leaf, 4)
				}
			}
		}
	}
}

type relocationEntry struct {
	rva   uint32
	type_ uint16
	extra uint16
}

func transformRelocations(data []byte, layout peLayout, rift riftTable, targetBase uint64, marker []byte) {
	directory := layout.directories[5]
	base, ok := layout.rawOffset(directory.rva)
	if !ok || directory.rva == 0 || base == 0 {
		if layout.machine == 0x14c && layout.imageBaseSize == 4 {
			transformUnlistedPointersX86(data, layout, rift, uint32(targetBase), marker)
		}
		return
	}
	end := min(len(data), base+int(directory.size))
	entries := make([]relocationEntry, 0)
	for block := base; block+8 <= end; {
		page, size := get32(data, block), int(get32(data, block+4))
		if size < 8 || block+size > end {
			break
		}
		count := (size - 8) / 2
		for index := 0; index < count; index++ {
			value := get16(data, block+8+index*2)
			type_ := value >> 12
			if type_ == 0 {
				break
			}
			rva := page + uint32(value&0xfff)
			entry := relocationEntry{rva: uint32(rift.mapForward(int64(rva))), type_: type_}
			if operand, ok := layout.rawOffset(rva); ok {
				switch type_ {
				case 3:
					// HIGHLOW stores only the low 32 bits of a VA, including
					// in PE32+ transition code. Subtract the image base in that
					// same modular domain before widening the resulting RVA.
					relative := int64(get32(data, operand) - uint32(layout.imageBase))
					put32(data, operand, uint32(int64(targetBase)+rift.mapForward(relative)))
					markPEBytes(marker, operand, 4)
				case 10:
					relative := int64(get64(data, operand)) - int64(layout.imageBase)
					put64(data, operand, uint64(int64(targetBase)+rift.mapForward(relative)))
					markPEBytes(marker, operand, 8)
				case 1, 2:
					markPEBytes(marker, operand, 2)
				case 4:
					markPEBytes(marker, operand, 2)
					if index+1 < count {
						index++
						entry.extra = get16(data, block+8+index*2)
					}
				}
			}
			entries = append(entries, entry)
		}
		block += size
	}
	sortRelocations(entries)
	limit := end
	for _, section := range layout.sections {
		if directory.rva >= section.rva && uint64(directory.rva) < uint64(section.rva)+uint64(max(section.rawSize, section.virtualSize)) {
			limit = min(len(data), base+int(section.rawSize-(directory.rva-section.rva)))
			break
		}
	}
	out := base
	for index := 0; index < len(entries) && out+8 <= limit; {
		page := entries[index].rva & 0xfffff000
		header := out
		out += 8
		body := out
		for index < len(entries) && entries[index].rva&0xfffff000 == page && out+2 <= limit {
			entry := entries[index]
			put16(data, out, entry.type_<<12|uint16(entry.rva&0xfff))
			out += 2
			if entry.type_ == 4 && out+2 <= limit {
				put16(data, out, entry.extra)
				out += 2
			}
			index++
		}
		if (out-body)/2%2 != 0 && out+2 <= limit {
			put16(data, out, 0)
			out += 2
		}
		put32(data, header, page)
		put32(data, header+4, uint32(out-header))
	}
}

// Without a relocation directory, native I386 RELOCS scans apparent VAs at
// every byte position after SizeOfHeaders, including non-executable data and
// padding. These can be accidental values (for example unaligned POGO bytes).
// MARK's bit1 only prevents instruction/branch ownership; bit2 excludes a
// four-byte candidate from this scan. This is MSDelta normalization, not PE
// relocation-loader semantics.
func transformUnlistedPointersX86(data []byte, layout peLayout, rift riftTable, targetBase uint32, marker []byte) {
	start := int(layout.headerSize)
	if start < 0 || len(data) < 4 {
		return
	}
	base := uint32(layout.imageBase)
	end := base + layout.imageSize
	for offset := start; offset < len(data)-4; {
		value := get32(data, offset)
		if value <= base || value >= end {
			offset++
			continue
		}
		if offset+4 > len(marker) {
			return
		}
		claimed := false
		for _, mark := range marker[offset : offset+4] {
			claimed = claimed || mark&2 != 0
		}
		if !claimed {
			put32(data, offset, targetBase+uint32(rift.mapForward(int64(value-base))))
			markPEBytes(marker, offset, 4)
		}
		// Even a marker-excluded in-range candidate consumes four bytes.
		offset += 4
	}
}

func sortRelocations(entries []relocationEntry) {
	for index := 1; index < len(entries); index++ {
		value := entries[index]
		place := index
		for place > 0 && entries[place-1].rva > value.rva {
			entries[place] = entries[place-1]
			place--
		}
		entries[place] = value
	}
}

func markPEBytes(marker []byte, offset, size int) {
	if offset < 0 || size <= 0 || offset >= len(marker) {
		return
	}
	for index := offset; index < min(len(marker), offset+size); index++ {
		marker[index] |= 1
	}
}

func markNonExecutablePE(marker []byte, layout peLayout) {
	for index := range marker {
		marker[index] |= 1
	}
	for _, section := range layout.sections {
		if section.characteristics&0x20000000 == 0 {
			continue
		}
		start := int(section.rawStart)
		// Branch targets may occupy executable raw padding beyond VirtualSize.
		// Target ownership covers the full raw extent, even though instruction
		// scanning is separately bounded by min(VirtualSize, SizeOfRawData).
		length := int(section.rawSize)
		if start < 0 || start >= len(marker) || length <= 0 {
			continue
		}
		for index := start; index < min(len(marker), start+length); index++ {
			marker[index] &^= 1
		}
	}
}

// The MARK transform claims headers and directory extents as instruction
// boundaries, not just individual rewritten fields. MSDelta applies the PE
// RVA-to-file mapping to every directory, including Security: although that
// directory is a file offset in the PE format, its delta marker coordinates
// follow this same mapping. Keep this compatibility rule local to MSDelta;
// certificate parsing must continue to use the actual file offset.
func markPEDirectories(marker []byte, layout peLayout) {
	mark := func(offset int, size uint64) {
		if offset < 0 || offset >= len(marker) {
			return
		}
		end := offset + int(min(size, uint64(len(marker)-offset)))
		for i := offset; i < end; i++ {
			marker[i] |= 3
		}
	}
	mark(0, uint64(layout.headerSize))
	// Use the delta coordinate map rather than section membership. Virtual
	// padding sections have no file coordinate and must not redirect a mark
	// into code; the rift also defines continuation across RVA gaps.
	rvaToFile := layout.fileToRVA().reverse()
	for _, directory := range layout.directories {
		if directory.rva == 0 || directory.size == 0 {
			continue
		}
		offset := rvaToFile.mapForward(int64(directory.rva))
		if offset >= 0 && offset < int64(len(marker)) {
			mark(int(offset), uint64(directory.size))
		}
	}
}

func markerRangeFree(marker []byte, offset, size int) bool {
	if offset < 0 || size < 0 || offset > len(marker)-size {
		return false
	}
	for _, value := range marker[offset : offset+size] {
		if value&1 != 0 {
			return false
		}
	}
	return true
}

func peBranchTargetReachable(layout peLayout, target uint32) bool {
	if target == 0 || target >= layout.imageSize {
		return false
	}
	// Only SizeOfHeaders has identity-mapped header coordinates. The RVA
	// alignment gap before the first section does not own any file bytes.
	if target < layout.headerSize {
		return true
	}
	for _, section := range layout.sections {
		span := max(section.virtualSize, section.rawSize)
		if target >= section.rva && uint64(target) < uint64(section.rva)+uint64(span) {
			return true
		}
	}
	return false
}

func peBranchTargetMarked(marker []byte, layout peLayout, target uint32) bool {
	index := int64(target)
	if target >= layout.headerSize {
		if offset, ok := layout.rawOffset(target); ok {
			index = int64(offset)
		} else {
			return true
		}
	}
	return index < 0 || index >= int64(len(marker)) || marker[index]&1 != 0
}

func transformCallsX86(data []byte, layout peLayout, rift riftTable, marker []byte) {
	for _, section := range layout.sections {
		if section.characteristics&0x20000000 == 0 {
			continue
		}
		start := int(section.rawStart)
		end := min(len(data), start+int(min(section.virtualSize, section.rawSize)))
		for position := start; position+5 <= end; {
			if data[position] != 0xe8 || !markerRangeFree(marker, position, 5) {
				position++
				continue
			}
			next := section.rva + uint32(position-start) + 5
			old := int32(get32(data, position+1))
			target := next + uint32(old)
			if !peBranchTargetReachable(layout, target) || peBranchTargetMarked(marker, layout, target) {
				position++
				continue
			}
			mapped := rift.mapForward(int64(target)) - rift.mapForward(int64(next))
			put32(data, position+1, uint32(int32(mapped)))
			position += 5
		}
	}
}

func transformJmpsX86(data []byte, layout peLayout, rift riftTable, marker []byte) {
	for _, section := range layout.sections {
		if section.characteristics&0x20000000 == 0 {
			continue
		}
		start := int(section.rawStart)
		end := min(len(data), start+int(min(section.virtualSize, section.rawSize)))
		// Native scans strictly before end-5, including after advancing past
		// a conditional jump's 0f prefix. A jump ending exactly at the section
		// boundary is not normalized; one trailing byte makes it participate.
		for position := start; position+5 < end; {
			displacementOpcode := position
			shortAllowed := true
			switch {
			case data[position] == 0xe9:
			case data[position] == 0x0f && position+1 < len(data) && data[position+1]&0xf0 == 0x80:
				displacementOpcode++
			default:
				position++
				continue
			}
			if data[displacementOpcode] != 0xe9 && marker[displacementOpcode-1]&1 != 0 {
				shortAllowed = false
			}
			if displacementOpcode+5 >= end || !markerRangeFree(marker, displacementOpcode, 5) {
				position++
				continue
			}
			old := int32(get32(data, displacementOpcode+1))
			if old >= -128 && old <= 127 {
				position++
				continue
			}
			next := section.rva + uint32(displacementOpcode-start) + 5
			target := next + uint32(old)
			if !peBranchTargetReachable(layout, target) || peBranchTargetMarked(marker, layout, target) {
				position++
				continue
			}
			mapped := int32(rift.mapForward(int64(target)) - rift.mapForward(int64(next)))
			if shortAllowed && mapped >= -128 && mapped <= 127 {
				if data[displacementOpcode] == 0xe9 {
					data[displacementOpcode] = 0xeb
					data[displacementOpcode+1] = byte(mapped)
				} else {
					data[displacementOpcode-1] = data[displacementOpcode]&0x0f | 0x70
					data[displacementOpcode] = byte(mapped)
				}
			} else {
				put32(data, displacementOpcode+1, uint32(mapped))
			}
			position = displacementOpcode + 5
		}
	}
}

func transformDisasmX64(data []byte, layout peLayout, rift riftTable, marker []byte) {
	transformDisasmX64Traced(data, layout, rift, marker, nil)
}

func transformDisasmX64Traced(data []byte, layout peLayout, rift riftTable, marker []byte, trace *peTransformTrace) {
	walkDisasmX64(data, layout, marker, func(offset int, rva uint32, instruction deltaX64Instruction) {
		field := offset + instruction.field
		old := int64(int32(get32(data, field)))
		// Native RVA arithmetic wraps in the unsigned 32-bit domain before
		// consulting the rift. Embedded data can decode as a displacement
		// whose signed sum is negative; that is a high RVA, not a coordinate
		// before the first breakpoint with the cyclic final displacement.
		next := int64(rva + uint32(instruction.length))
		target := int64(uint32(next) + uint32(old))
		mapped := rift.mapForward(target) - rift.mapForward(next)
		if trace != nil {
			trace.events = append(trace.events, PETransformInfo{
				RawStart: field, RawEnd: field + 4,
				InstructionRaw: offset, InstructionRVA: int(rva),
				InstructionLength: instruction.length, Field: instruction.field,
				Old: int32(old), Mapped: int32(mapped), Target: target,
				TargetReachable: target >= 0 && target <= int64(^uint32(0)) && peBranchTargetReachable(layout, uint32(target)),
				TargetMarked:    target < 0 || target > int64(^uint32(0)) || peBranchTargetMarked(marker, layout, uint32(target)),
			})
		}
		put32(data, field, uint32(int32(mapped)))
	})
}

func walkDisasmX64(data []byte, layout peLayout, marker []byte, visit func(offset int, rva uint32, instruction deltaX64Instruction)) {
	directory := layout.directories[3]
	pdata, ok := layout.rawOffset(directory.rva)
	if !ok || directory.rva == 0 {
		return
	}
	count := min(int(directory.size/12), (len(data)-pdata)/12)
	for index := range count {
		begin, end := get32(data, pdata+index*12), get32(data, pdata+index*12+4)
		function, ok := layout.rawOffset(begin)
		if !ok || begin == 0 || end <= begin {
			continue
		}
		for rva, offset := begin, function; rva < end && offset < len(data); {
			// TransformBase's byte map is shared by all PE transforms. The native
			// AMD64 runner never begins decoding on a byte claimed by an earlier
			// transform. This one-byte resynchronization is important for broad
			// .pdata ranges that contain embedded data.
			if offset < len(marker) && marker[offset]&3 != 0 {
				rva++
				offset++
				continue
			}
			window := min(15, int(end-rva), len(data)-offset)
			instruction := decodeDeltaX64(data[offset : offset+window])
			if instruction.length <= 0 {
				break
			}
			advance := instruction.length
			// Bit 1 marks an interior boundary that the native runner will not
			// decode across. Advance only to that boundary, then let the start-byte
			// rule above consume it. Bit 0 alone (for example a relocation operand)
			// does not truncate an instruction which began before the marked bytes.
			for inner := 1; inner < instruction.length && offset+inner < len(marker); inner++ {
				if marker[offset+inner]&2 != 0 {
					advance = inner
					break
				}
			}
			if advance == instruction.length && instruction.remap && instruction.field >= 0 && instruction.field+4 <= instruction.length {
				visit(offset, rva, instruction)
			}
			rva += uint32(advance)
			offset += advance
		}
	}
}

func transformPdataX64(data []byte, layout peLayout, rift riftTable) {
	directory := layout.directories[3]
	pdata, ok := layout.rawOffset(directory.rva)
	if !ok || directory.rva == 0 {
		return
	}
	count := min(int(directory.size/12), (len(data)-pdata)/12)
	for index := range count {
		offset := pdata + index*12
		unwind := get32(data, offset+8)
		if unwindOffset, ok := layout.rawOffset(unwind); ok && (unwindOffset < pdata || unwindOffset > pdata+int(directory.size)) && unwindOffset+4 <= len(data) && data[unwindOffset]&0x38 != 0 {
			slot := unwindOffset + 4 + ((int(data[unwindOffset+2])+1)/2)*4
			if slot+4 <= len(data) {
				mapRVA32(data, slot, rift)
			}
		}
		for field := 0; field < 12; field += 4 {
			mapRVA32(data, offset+field, rift)
		}
	}
}

func mapRVA32(data []byte, offset int, rift riftTable) {
	value := get32(data, offset)
	if value != 0 {
		put32(data, offset, uint32(rift.mapForward(int64(value))))
	}
}

func get16(data []byte, offset int) uint16 {
	if offset < 0 || offset+2 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint16(data[offset:])
}

func get32(data []byte, offset int) uint32 {
	if offset < 0 || offset+4 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint32(data[offset:])
}

func get64(data []byte, offset int) uint64 {
	if offset < 0 || offset+8 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint64(data[offset:])
}

func put16(data []byte, offset int, value uint16) {
	if offset >= 0 && offset+2 <= len(data) {
		binary.LittleEndian.PutUint16(data[offset:], value)
	}
}

func put32(data []byte, offset int, value uint32) {
	if offset >= 0 && offset+4 <= len(data) {
		binary.LittleEndian.PutUint32(data[offset:], value)
	}
}

func put64(data []byte, offset int, value uint64) {
	if offset >= 0 && offset+8 <= len(data) {
		binary.LittleEndian.PutUint64(data[offset:], value)
	}
}
