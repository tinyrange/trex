package ckd

import (
	"bytes"
	"fmt"
)

// AttributeCell preserves an IGW attribute-directory key and its uninterpreted
// value. Keys use a 20-byte page anchor, common-prefix compression and trailing
// zero suppression. Values differ between internal and leaf pages.
type AttributeCell struct {
	Flags byte // Retained verbatim; not interpreted as entry liveness.
	Key   [20]byte
	Value []byte
}

// AttributePage is a decoded page, not a resolved PDSE/HFS directory tree.
// In particular, internal child identifiers are not physical page addresses.
type AttributePage struct {
	Level byte
	Cells []AttributeCell
}

// ParseAttributePage reads the observed IGW AD page layout. It does not scan
// free space: live groups end at the free-space limit minus the free-byte count.
// Returned values own their bytes and remain valid after the input is reused.
func ParseAttributePage(b []byte) (*AttributePage, error) {
	bad := func(reason string) (*AttributePage, error) {
		return nil, fmt.Errorf("ckd IGW attribute page: %s", reason)
	}
	if len(b) != 4096 || b[0] != 52 || b[1] != 1 || !bytes.Equal(b[11:13], []byte{0xc1, 0xc4}) || b[25] != 20 || be.Uint16(b[4094:]) != 0xa55a {
		return bad("unsupported header or trailer")
	}
	free, limit := int(be.Uint16(b[48:50])), int(be.Uint16(b[50:52]))
	if limit > 4094 || free > limit || limit-free < 72 {
		return bad("invalid free-space bounds")
	}
	end := limit - free
	out := &AttributePage{Level: b[30]}
	var previous [20]byte
	copy(previous[:], b[52:72])
	for pos := 72; pos < end; {
		if end-pos < 5 {
			return bad("short group header")
		}
		size, used := int(be.Uint16(b[pos:])), int(be.Uint16(b[pos+2:]))
		if size < 5 || size > end-pos || used != size {
			return bad("invalid or unsupported group lengths")
		}
		next := pos + size
		count := int(b[pos+4])
		if count == 0 {
			return bad("empty group")
		}
		cell := pos + 5
		for i := 0; i < count; i++ {
			if next-cell < 5 {
				return bad("short cell header")
			}
			length := int(be.Uint16(b[cell:]))
			if length < 5 || length > next-cell || (b[cell+2] != 0xc0 && b[cell+2] != 0xd5 && b[cell+2] != 0xe5 && b[cell+2] != 0xd6 && b[cell+2] != 0xe6 && b[cell+2] != 0xec) {
				return bad(fmt.Sprintf("invalid cell length %d or unsupported flags %#02x at offset %#x", length, b[cell+2], cell))
			}
			prefix, padding := int(b[cell+3]), int(b[cell+4])
			suffix := 20 - prefix - padding
			if prefix > 20 || suffix < 0 || suffix > length-5 {
				return bad("invalid compressed key")
			}
			var key [20]byte
			copy(key[:prefix], previous[:prefix])
			copy(key[prefix:], b[cell+5:cell+5+suffix])
			// Internal separators can be shortened prefixes. Their decoded
			// byte strings need not sort after the preceding full key; the
			// tree reader verifies actual leaf ordering across child ranges.
			if out.Level == 1 && bytes.Compare(key[:], previous[:]) < 0 {
				return bad(fmt.Sprintf("unordered key at %#x flags %#02x: %x after %x", cell, b[cell+2], key, previous))
			}
			out.Cells = append(out.Cells, AttributeCell{Flags: b[cell+2], Key: key, Value: bytes.Clone(b[cell+5+suffix : cell+length])})
			previous = key
			cell += length
		}
		if cell != next {
			return bad("unaccounted group bytes")
		}
		pos = next
	}
	return out, nil
}
