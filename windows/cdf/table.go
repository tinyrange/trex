package cdf

import (
	"encoding/binary"
	"fmt"
)

// Table is the bounded FileMap subset of CDF tables: kind 6 with header flags 1
// (32-bit hashes, string IDs, blob IDs), or kind 9 with flags 0 (uint32 keys and
// blob IDs). Other native compact/policy variants are deliberately unsupported.
// IDs are unresolved; validating a container does not validate these references.
type Table struct {
	Kind                 uint8
	Hashes, Keys, Values []uint32
}

func ParseTable(kind uint8, data []byte) (*Table, error) {
	if len(data) < 4 || len(data) > MaxSize {
		return nil, fmt.Errorf("CDF table: invalid size")
	}
	word := binary.LittleEndian.Uint32(data[:4])
	flags, n := uint8(word), int(word>>8)
	width := 8
	switch kind {
	case 6:
		if flags != 1 {
			return nil, fmt.Errorf("CDF table: unsupported string flags %#x", flags)
		}
		width = 12
	case 9:
		if flags != 0 {
			return nil, fmt.Errorf("CDF table: unsupported ulong flags %#x", flags)
		}
	default:
		return nil, fmt.Errorf("CDF table: unsupported kind %d", kind)
	}
	if n > 1<<20 || n > (len(data)-4)/width || len(data) != 4+n*width {
		return nil, fmt.Errorf("CDF table: invalid entry extent")
	}
	t := &Table{Kind: kind}
	off := 4
	read := func() []uint32 {
		out := make([]uint32, n)
		for i := range out {
			out[i] = binary.LittleEndian.Uint32(data[off : off+4])
			off += 4
		}
		return out
	}
	if kind == 6 {
		t.Hashes = read()
	}
	t.Keys = read()
	t.Values = read()
	if err := t.validate(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Table) validate() error {
	if t == nil || (t.Kind != 6 && t.Kind != 9) {
		return fmt.Errorf("CDF table: unsupported kind")
	}
	n := len(t.Keys)
	if n > 1<<20 || len(t.Values) != n || (t.Kind == 6 && len(t.Hashes) != n) || (t.Kind == 9 && len(t.Hashes) != 0) {
		return fmt.Errorf("CDF table: inconsistent columns")
	}
	seen := make(map[uint32]bool, n)
	for i, k := range t.Keys {
		if seen[k] {
			return fmt.Errorf("CDF table: duplicate key ID %d", k)
		}
		seen[k] = true
		if i == 0 {
			continue
		}
		if t.Kind == 9 && t.Keys[i-1] >= k {
			return fmt.Errorf("CDF table: unordered integer keys")
		}
		if t.Kind == 6 && t.Hashes[i-1] > t.Hashes[i] {
			return fmt.Errorf("CDF table: unordered hashes")
		}
	}
	return nil
}

// Marshal preserves entry ordering, including distinct keys with equal hashes.
// Callers supply valid hashes and resolve key/value IDs in the enclosing document.
// It does not invent a secondary ordering for native hash collisions.
func (t *Table) Marshal() ([]byte, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	n := len(t.Keys)
	flags, width := 0, 8
	if t.Kind == 6 {
		flags, width = 1, 12
	}
	out := make([]byte, 4+n*width)
	binary.LittleEndian.PutUint32(out[:4], uint32(n)<<8|uint32(flags))
	off := 4
	for _, column := range [][]uint32{t.Hashes, t.Keys, t.Values} {
		for _, v := range column {
			binary.LittleEndian.PutUint32(out[off:off+4], v)
			off += 4
		}
	}
	return out, nil
}
