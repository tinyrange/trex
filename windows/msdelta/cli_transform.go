package msdelta

import "math/bits"

// CLI remapping changes references in the source's existing representation;
// it does not rearrange rows or widen cells to the target table layout.
type cliRemap struct {
	heaps  [4]riftTable
	tables [64]riftTable
}

func newCLIRemap(m *CLIPreprocessInfo) cliRemap {
	var result cliRemap
	if m == nil {
		return result
	}
	convert := func(entries []PERiftEntry) riftTable {
		r := riftTable{entries: make([]riftEntry, len(entries))}
		for i, e := range entries {
			r.entries[i] = riftEntry{source: e.Source, target: e.Target}
		}
		return r
	}
	for i, entries := range m.HeapMaps {
		result.heaps[i] = convert(entries)
	}
	for i, entries := range m.TableMaps {
		result.tables[i] = convert(entries)
	}
	return result
}

func cliMapIndex(r riftTable, value uint32) uint32 {
	if value == 0 {
		return 0
	}
	return uint32(r.mapForward(int64(value)))
}

func (r *cliRemap) coded(kind int, value uint32) uint32 {
	tables := cliCodedTables[kind-cliTypeDefOrRef]
	shift := uint(bits.Len(uint(len(tables) - 1)))
	tag := value & ((1 << shift) - 1)
	if int(tag) >= len(tables) || tables[tag] < 0 {
		return value
	}
	rid := cliMapIndex(r.tables[tables[tag]], value>>shift)
	if rid > ^uint32(0)>>shift {
		return value
	}
	return rid<<shift | tag
}

func transformCLIMetadata(dst, source []byte, m *cliMetadata, target *CLIPreprocessInfo, rva riftTable) error {
	remap := newCLIRemap(target)
	// Read every reference from the immutable source. A shared blob must be
	// visited once even if several rows/tables refer to the same signature.
	visited := make(map[uint32]bool)
	for table := range cliColumns {
		columns := m.columns(table)
		for row := uint32(0); row < m.Rows[table]; row++ {
			off := m.tableOffsets[table] + int(row)*m.rowSizes[table]
			for _, kind := range columns {
				width := m.columnWidth(kind)
				value := get32(source, off)
				if width == 2 {
					value = uint32(get16(source, off))
				}
				mapped := value
				switch {
				case kind < 64:
					mapped = cliMapIndex(remap.tables[kind], value)
				case kind >= cliTypeDefOrRef && kind <= cliTypeOrMethodDef:
					mapped = remap.coded(kind, value)
				case kind == cliStrings:
					mapped = cliMapIndex(remap.heaps[0], value)
				case kind == cliGUID:
					mapped = cliMapIndex(remap.heaps[3], value)
				case kind == cliBlob:
					mapped = cliMapIndex(remap.heaps[2], value)
					if value != 0 && !visited[value] && cliSignatureTable(table) {
						visited[value] = true
						transformCLISignature(dst, source, m.Streams[2], value, table, &remap)
					}
				case kind == cliRVA:
					mapped = cliMapIndex(rva, value)
				}
				if width == 4 {
					put32(dst, off, mapped)
				} else {
					// Normalization preserves the source cell width, including
					// low-word truncation when the target reference has widened.
					// Retaining the old index on overflow corrupts patch copies.
					put16(dst, off, uint16(mapped))
				}
				off += width
			}
		}
	}
	return nil
}

func cliSignatureTable(table int) bool {
	switch table {
	case 4, 6, 10, 17, 23, 27:
		return true
	}
	return false
}

// ECMA-335 II.23.2 compressed unsigned integers. Source widths are preserved
// because growing a signature here would invalidate the patch's coordinates.
func cliCompressed(data []byte) (uint32, int) {
	if len(data) == 0 {
		return 0, 0
	}
	if data[0] < 0x80 {
		return uint32(data[0]), 1
	}
	if data[0] < 0xc0 && len(data) >= 2 {
		return uint32(data[0]&0x3f)<<8 | uint32(data[1]), 2
	}
	if data[0] < 0xe0 && len(data) >= 4 {
		return uint32(data[0]&0x1f)<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]), 4
	}
	return 0, 0
}

type cliSignature struct {
	source, dst []byte
	pos         int
	remap       *cliRemap
}

func transformCLISignature(dst, source []byte, stream CLIStreamInfo, index uint32, table int, remap *cliRemap) {
	start, end := uint64(stream.Offset)+uint64(index), uint64(stream.Offset)+uint64(stream.Size)
	if start >= end || end > uint64(len(source)) || end > uint64(len(dst)) {
		return
	}
	length, prefix := cliCompressed(source[start:end])
	start += uint64(prefix)
	if prefix == 0 || uint64(length) > end-start {
		return
	}
	w := cliSignature{source: source[start : start+uint64(length)], dst: dst[start : start+uint64(length)], remap: remap}
	if table == 27 {
		// TypeSpec enters native's bare type walker, not the outer
		// method/field modifier boundary. A root custom modifier stops
		// normalization; neither its token nor the following type is read.
		if len(w.source) != 0 && (w.source[0] == 0x1f || w.source[0] == 0x20) {
			return
		}
		w.typ(0)
		return
	}
	if table == 4 || (table == 10 && len(w.source) != 0 && w.source[0] == 6) {
		w.byte()
		w.typ(0)
		return
	}
	w.method(0)
}

func (w *cliSignature) byte() (byte, bool) {
	if w.pos >= len(w.source) {
		return 0, false
	}
	v := w.source[w.pos]
	w.pos++
	return v, true
}

func (w *cliSignature) number() (uint32, bool) {
	v, n := cliCompressed(w.source[w.pos:])
	w.pos += n
	return v, n != 0
}

func (w *cliSignature) token() bool {
	start := w.pos
	v, ok := w.number()
	if !ok {
		return false
	}
	// Native signature normalization uses the TypeDef map for both CLASS
	// and VALUETYPE operands tagged TypeDef or TypeRef, preserving the tag.
	// Ordinary metadata coded indexes and IL tokens retain their own maps.
	lookup := v
	if v&3 == 1 {
		lookup &^= 3
	}
	mapped := w.remap.coded(cliTypeDefOrRef, lookup)
	if v&3 == 1 {
		mapped |= 1
	}
	// Re-encode at the shortest representable width, using the old width
	// only as a capacity. Narrowing neither shifts the following bytes nor
	// clears the old trailing bytes; traversal keeps the source cursor.
	width := w.pos - start
	switch {
	case mapped <= 0x7f:
		w.dst[start] = byte(mapped)
	case mapped <= 0x3fff && width >= 2:
		w.dst[start] = 0x80 | byte(mapped>>8)
		w.dst[start+1] = byte(mapped)
	case mapped <= 0x1fffffff && width >= 4:
		w.dst[start] = 0xc0 | byte(mapped>>24)
		w.dst[start+1] = byte(mapped >> 16)
		w.dst[start+2] = byte(mapped >> 8)
		w.dst[start+3] = byte(mapped)
	}
	return true
}

func (w *cliSignature) method(depth int) bool {
	if depth >= 64 {
		return false
	}
	call, ok := w.byte()
	if !ok {
		return false
	}
	// StandAloneSig also contains FIELD signatures. Their next byte is an
	// element type, not a method parameter count.
	if call&0xf == 6 {
		if w.pos < len(w.source) && w.source[w.pos] == 0x10 {
			return false
		}
		return w.typ(depth + 1)
	}
	// Native does not skip a generic method's arity. The next integer is
	// always treated as the parameter count, leaving the actual parameter
	// count to be interpreted as an element type by the same cursor rules.
	count, ok := w.number()
	if !ok {
		return false
	}
	if call&0xf != 7 {
		count++ // LocalVarSig has no return type.
	} else if count != 0 {
		// Native MSDelta visits only the first local type, not the remaining
		// LocalVarSig entries. This is independent of whether its token fits
		// the source width; a representable first-token control still leaves
		// every later local unchanged.
		count = 1
	}
	for i := uint32(0); i < count; i++ {
		// At a method's outer type boundary, custom modifiers precede
		// the non-consuming VOID/TYPEDBYREF check. A VOID nested inside
		// PTR is different: the recursive type walker consumes it normally.
		for w.pos < len(w.source) && (w.source[w.pos] == 0x1f || w.source[w.pos] == 0x20) {
			w.pos++
			if !w.token() {
				return false
			}
		}
		// The native method walker recognizes VOID and TYPEDBYREF without
		// advancing its cursor. Remaining iterations see the same byte and
		// cannot remap anything. This also applies to an unconsumed generic
		// arity of one; do not interpret the following bytes as parameters.
		if call&0xf != 7 && w.pos < len(w.source) && (w.source[w.pos] == 1 || w.source[w.pos] == 0x16) {
			return true
		}
		if !w.typ(depth + 1) {
			return false
		}
	}
	return true
}

func (w *cliSignature) typ(depth int) bool {
	if depth >= 64 {
		return false
	}
	for {
		kind, ok := w.byte()
		if !ok {
			return false
		}
		switch {
		case kind >= 1 && kind <= 0xe, kind == 0x16, kind == 0x18, kind == 0x19, kind == 0x1c:
			return true
		case kind == 0x0f, kind == 0x10, kind == 0x1d:
			return w.typ(depth + 1)
		case kind == 0x11, kind == 0x12:
			return w.token()
		case kind == 0x13, kind == 0x1e:
			_, ok := w.number()
			return ok
		case kind == 0x1f, kind == 0x20:
			if !w.token() {
				return false
			}
		case kind == 0x14:
			if !w.typ(depth + 1) {
				return false
			}
			if _, ok := w.number(); !ok {
				return false
			}
			for j := 0; j < 2; j++ {
				count, ok := w.number()
				if !ok {
					return false
				}
				for i := uint32(0); i < count; i++ {
					if _, ok := w.number(); !ok {
						return false
					}
				}
			}
			return true
		case kind == 0x15:
			// MSDelta only consumes the GENERICINST constructor here. The
			// argument count remains at the cursor and the caller's remaining
			// type iterations interpret it as an element type. In particular,
			// arity one stops a method walk, while arity two can continue.
			// This is compatibility behavior, not ECMA-335 generic traversal.
			return w.typ(depth + 1)
		case kind == 0x1b:
			// Native MSDelta stops the signature walk at FNPTR. It does not
			// normalize the nested method signature or resume at later outer
			// parameters. This differs from an ECMA-335 recursive traversal.
			return false
		case kind&0xf0 == 0x40: // sentinel/pinned modifiers
		default:
			return false
		}
	}
}
