package ckd

import (
	"bytes"
	"fmt"

	"github.com/tinyrange/trex/storage"
)

// OpenProgramObject provides an optional gap-expanded byte view, NOT the stored
// program file. Use OpenStoredProgramObject for canonical member contents.
// IEWPGSTB entries describe page-aligned gaps in expanded coordinates and the
// cumulative omitted count. Layouts without this table fail explicitly; they
// can still be valid stored objects. This view is not a relinked executable.
func OpenProgramObject(source storage.Reader) (*Content, error) {
	bad := func(s string) (*Content, error) { return nil, fmt.Errorf("PDSE program: %s", s) }
	read := func(off, size int64) ([]byte, error) {
		if off < 0 || size < 0 || off > source.Size() || size > source.Size()-off || size > 1<<20 {
			return nil, fmt.Errorf("PDSE program: metadata outside allocation or over limit")
		}
		b := make([]byte, int(size))
		_, err := source.ReadAt(b, off)
		return b, err
	}
	h, err := read(0, 24)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(h[:8], []byte{0xc9, 0xc5, 0xe6, 0xd7, 0xd3, 0xd4, 0xc8, 0x40}) {
		return bad("invalid header")
	}
	size := int64(be.Uint32(h[16:]))
	if size == source.Size() {
		return &Content{source: source, size: size, spans: []span{{0, size, 0}}}, nil
	}
	if size < source.Size() || (h[12] < 2 || h[12] > 4) {
		return bad("unsupported size or version")
	}
	count := int64(be.Uint32(h[20:]))
	if count < 1 || count > 256 || int64(be.Uint32(h[8:])) != 24+count*12 {
		return bad("invalid section table")
	}
	sections, err := read(24, count*12)
	if err != nil {
		return nil, err
	}
	var indexOff, indexLen int64
	for i := int64(0); i < count; i++ {
		s := sections[i*12:]
		if be.Uint16(s) == 6 {
			if indexLen != 0 {
				return bad("duplicate loader index")
			}
			indexOff, indexLen = int64(be.Uint32(s[4:])), int64(be.Uint32(s[8:]))
		}
	}
	if indexLen < 20 {
		return bad("missing loader index")
	}
	index, err := read(indexOff, indexLen)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(index[:8], []byte{0xc9, 0xc5, 0xe6, 0xd3, 0xc9, 0xc4, 0xe7, 0x40}) || be.Uint32(index[8:]) != 20 || index[12] != 1 {
		return bad("unsupported loader index")
	}
	n := int64(be.Uint32(index[16:]))
	if n > (indexLen-20)/12 {
		return bad("invalid loader index count")
	}
	var tableOff, tableLen int64
	for i := int64(0); i < n; i++ {
		e := index[20+i*12:]
		if e[0] == 3 {
			if tableLen != 0 {
				return bad("duplicate gap table")
			}
			tableOff, tableLen = int64(be.Uint32(e[4:])), int64(be.Uint32(e[8:]))
		}
	}
	if tableLen < 20 {
		return bad("missing gap table")
	}
	t, err := read(tableOff, tableLen)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(t[:8], []byte{0xc9, 0xc5, 0xe6, 0xd7, 0xc7, 0xe2, 0xe3, 0xc2}) || int64(be.Uint32(t[8:])) != tableLen || t[12] != 1 {
		return bad("unsupported gap table")
	}
	n = int64(be.Uint32(t[16:]))
	if n < 1 || n > (tableLen-20)/12 || 20+n*12 != tableLen {
		return bad("invalid gap count")
	}
	out := &Content{source: source, size: size}
	var logical, omitted int64
	metadataEnd := max(24+count*12, indexOff+indexLen, tableOff+tableLen)
	for i := int64(0); i < n; i++ {
		e := t[20+i*12:]
		start, end, prior := int64(be.Uint32(e)), int64(be.Uint32(e[4:]))+1, int64(be.Uint32(e[8:]))
		if start < logical || start < metadataEnd || end <= start || end > size || start%4096 != 0 || end%4096 != 0 || prior != omitted {
			return bad("invalid gap range or cumulative offset")
		}
		if start > logical {
			out.spans = append(out.spans, span{logical - omitted, start - logical, logical})
		}
		out.spans = append(out.spans, span{-1, end - start, start})
		omitted += end - start
		logical = end
	}
	if size-omitted != source.Size() {
		return bad("gaps do not reconcile allocation size")
	}
	if logical < size {
		out.spans = append(out.spans, span{logical - omitted, size - logical, logical})
	}
	return out, nil
}
