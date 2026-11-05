package windows

import (
	"encoding/binary"
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// neInternalRelocation describes a selector or far-pointer reference in the
// added code. Target 0 denotes the new code, -1 the new data, -2 a movable
// export whose ordinal is Offset, and a positive value an existing segment.
// Existing loader fixups remain untouched.
type neInternalRelocation struct{ SourceType, Source, Target, Offset int }

func extendWindowsNE(source, code, data []byte, relocations []neInternalRelocation, redirects, aliases map[int]int) ([]byte, error) {
	m, err := parseWindowsNEModule(source)
	if err != nil {
		return nil, err
	}
	entries, err := parseWindowsNEExports(source)
	if err != nil {
		return nil, err
	}
	if m.segmentCount > 252 || len(code) == 0 || len(code) > 65536 || len(data) == 0 || len(data) > 65536 || len(relocations) > 65535 {
		return nil, fmt.Errorf("NE extension exceeds segment limits")
	}
	codeSegment, dataSegment := m.segmentCount+1, m.segmentCount+2
	byOrdinal := make(map[int]windowsNEExport)
	last := 0
	for _, e := range entries {
		byOrdinal[e.Ordinal] = e
		if e.Ordinal > last {
			last = e.Ordinal
		}
	}
	// Keep original entries addressable when a wrapper calls them directly.
	// Windows patches exported WIN prologues with the module's data selector;
	// an alias preserves that loader behavior for a redirected original entry.
	originalEntries := make(map[int]windowsNEExport, len(byOrdinal))
	for ordinal, entry := range byOrdinal {
		originalEntries[ordinal] = entry
	}
	for ordinal, original := range aliases {
		entry, ok := originalEntries[original]
		_, exists := byOrdinal[ordinal]
		_, redirected := redirects[ordinal]
		if !ok || ordinal < 1 || ordinal > 65535 || exists || redirected {
			return nil, fmt.Errorf("invalid NE alias %d for %d", ordinal, original)
		}
		entry.Ordinal = ordinal
		byOrdinal[ordinal] = entry
		if ordinal > last {
			last = ordinal
		}
	}
	for ordinal, offset := range redirects {
		if ordinal < 1 || ordinal > 65535 || offset < 0 || offset >= len(code) {
			return nil, fmt.Errorf("invalid NE redirected entry %d:%d", ordinal, offset)
		}
		e := byOrdinal[ordinal]
		e.Ordinal, e.Segment, e.Offset, e.Flags = ordinal, codeSegment, offset, 3
		e.Movable, e.Constant = false, false
		byOrdinal[ordinal] = e
		if ordinal > last {
			last = ordinal
		}
	}
	// Preserve every original absolute segment/resource offset. A new copy of
	// the NE header and tables follows the original image; only e_lfanew changes.
	// This avoids relocating opaque original code, resources, and fixup chains.
	header := append([]byte(nil), source[m.ne:m.nonresident]...)
	insert := m.segments - m.ne + m.segmentCount*8
	if insert > len(header) {
		return nil, fmt.Errorf("segment table exceeds NE header")
	}
	header = append(header[:insert:insert], append(make([]byte, 16), header[insert:]...)...)
	for _, field := range []int{4, 0x24, 0x26, 0x28, 0x2a} {
		offset := int(binary.LittleEndian.Uint16(header[field:]))
		if offset >= insert {
			if offset > 65535-16 {
				return nil, fmt.Errorf("NE table offset overflows")
			}
			binary.LittleEndian.PutUint16(header[field:], uint16(offset+16))
		}
	}
	binary.LittleEndian.PutUint16(header[0x1c:], uint16(m.segmentCount+2))
	binary.LittleEndian.PutUint32(header[8:], 0) // checksum no longer describes this image
	// The original fast-load range does not cover the appended segments.
	header[0x37] &^= 0x08
	binary.LittleEndian.PutUint32(header[0x38:], 0)
	entryStart := len(header)
	if entryStart > 65535 {
		return nil, fmt.Errorf("NE header exceeds relative offsets")
	}
	movableCount := 0
	for ordinal := 1; ordinal <= last; ordinal++ {
		e, ok := byOrdinal[ordinal]
		if !ok {
			header = append(header, 1, 0)
			continue
		}
		kind := e.Segment
		if e.Constant {
			kind = 254
		}
		if e.Movable {
			movableCount++
			header = append(header, 1, 255, byte(e.Flags), 0xcd, 0x3f, byte(e.Segment), byte(e.Offset), byte(e.Offset>>8))
		} else {
			header = append(header, 1, byte(kind), byte(e.Flags), byte(e.Offset), byte(e.Offset>>8))
		}
	}
	header = append(header, 0)
	binary.LittleEndian.PutUint16(header[0x30:], uint16(movableCount))
	if len(header)-entryStart > 65535 {
		return nil, fmt.Errorf("NE entry table exceeds 16-bit length")
	}
	binary.LittleEndian.PutUint16(header[4:], uint16(entryStart))
	binary.LittleEndian.PutUint16(header[6:], uint16(len(header)-entryStart))
	result := padWindowsNEParagraph(append([]byte(nil), source...))
	newNE := len(result)
	binary.LittleEndian.PutUint32(header[0x2c:], uint32(newNE+len(header)))
	header = append(header, source[m.nonresident:m.nonresident+m.nonresidentSize]...)
	result = append(result, header...)
	appendSegment := func(payload []byte, slot, flags int) error {
		alignment := 1 << m.alignShift
		for len(result)%alignment != 0 {
			result = append(result, 0)
		}
		sector := len(result) >> m.alignShift
		if sector > 65535 {
			return fmt.Errorf("NE appended segment offset overflows")
		}
		entry := newNE + (m.segments - m.ne) + slot*8
		binary.LittleEndian.PutUint16(result[entry:], uint16(sector))
		binary.LittleEndian.PutUint16(result[entry+2:], uint16(len(payload)))
		binary.LittleEndian.PutUint16(result[entry+4:], uint16(flags))
		binary.LittleEndian.PutUint16(result[entry+6:], uint16(len(payload)))
		result = append(result, payload...)
		return nil
	}
	codeFlags := 0x60 // fixed, preload, executable
	if len(relocations) > 0 {
		codeFlags |= 0x100
	}
	if err := appendSegment(code, m.segmentCount, codeFlags); err != nil {
		return nil, err
	}
	if len(relocations) > 0 {
		result = append(result, byte(len(relocations)), byte(len(relocations)>>8))
		seen := map[int]bool{}
		for _, r := range relocations {
			width := 2
			if r.SourceType == 3 {
				width = 4
			} else if r.SourceType != 2 {
				return nil, fmt.Errorf("unsupported NE relocation source type %d", r.SourceType)
			}
			if r.Source < 0 || r.Source > len(code)-width || binary.LittleEndian.Uint16(code[r.Source:]) != 0xffff {
				return nil, fmt.Errorf("invalid NE relocation source %d", r.Source)
			}
			for at := r.Source; at < r.Source+width; at++ {
				if seen[at] {
					return nil, fmt.Errorf("overlapping NE relocation source %d", r.Source)
				}
				seen[at] = true
			}
			target := r.Target
			switch target {
			case 0:
				target = codeSegment
			case -1:
				target = dataSegment
			case -2:
				entry, ok := byOrdinal[r.Offset]
				if !ok || !entry.Movable || entry.Constant {
					return nil, fmt.Errorf("NE relocation requires a movable export: %d", r.Offset)
				}
				target = 255
			}
			if target < 1 || (target > dataSegment && r.Target != -2) || r.Offset < 0 || r.Offset > 65535 {
				return nil, fmt.Errorf("invalid NE relocation target")
			}
			result = append(result, byte(r.SourceType), 0, byte(r.Source), byte(r.Source>>8), byte(target), 0, byte(r.Offset), byte(r.Offset>>8))
		}
	}
	if err := appendSegment(data, m.segmentCount+1, 0x61); err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(result[0x3c:], uint32(newNE))
	return result, nil
}

func windowsNEExtendBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sourceValue, codeValue, dataValue starlark.Value
	var relocations *starlark.List
	var redirects, aliases *starlark.Dict
	if err := starlark.UnpackArgs("ne_extend", args, kwargs, "source", &sourceValue, "code", &codeValue, "data", &dataValue, "relocations", &relocations, "exports", &redirects, "aliases?", &aliases); err != nil {
		return nil, err
	}
	source, err := bytesForBinaryValueLimited(sourceValue, windowsNEFastBootMaximum)
	if err != nil {
		return nil, err
	}
	code, err := bytesForBinaryValueLimited(codeValue, 65536)
	if err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(dataValue, 65536)
	if err != nil {
		return nil, err
	}
	var rows []neInternalRelocation
	for i := 0; i < relocations.Len(); i++ {
		tuple, ok := relocations.Index(i).(starlark.Tuple)
		if !ok || len(tuple) != 4 {
			return nil, fmt.Errorf("ne_extend: relocation must be a 4-integer tuple")
		}
		r := neInternalRelocation{}
		for j, p := range []*int{&r.SourceType, &r.Source, &r.Target, &r.Offset} {
			if err := starlark.AsInt(tuple[j], p); err != nil {
				return nil, err
			}
		}
		rows = append(rows, r)
	}
	exports := map[int]int{}
	for _, item := range redirects.Items() {
		var ordinal, offset int
		if err := starlark.AsInt(item[0], &ordinal); err != nil {
			return nil, err
		}
		if err := starlark.AsInt(item[1], &offset); err != nil {
			return nil, err
		}
		exports[ordinal] = offset
	}
	aliasEntries := map[int]int{}
	if aliases != nil {
		for _, item := range aliases.Items() {
			var ordinal, original int
			if err := starlark.AsInt(item[0], &ordinal); err != nil {
				return nil, err
			}
			if err := starlark.AsInt(item[1], &original); err != nil {
				return nil, err
			}
			aliasEntries[ordinal] = original
		}
	}
	result, err := extendWindowsNE(source, code, data, rows, exports, aliasEntries)
	if err != nil {
		return nil, fmt.Errorf("ne_extend: %w", err)
	}
	return &starfile.Bytes{Name: "extended.exe", Data: result}, nil
}
