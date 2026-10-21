// Package appledouble reads RFC1740 version2 AppleDouble fork containers.
// Entry payloads remain borrowed views. Unknown IDs are retained, not discarded.
package appledouble

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
)

type Entry struct {
	ID   uint32
	Data storage.Reader
}
type part struct {
	storage.Reader
	off, size int64
}

func (p part) Size() int64 { return p.size }
func (p part) ReadAt(b []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("appledouble: negative offset")
	}
	if len(b) == 0 {
		return 0, nil
	}
	if off >= p.size {
		return 0, io.EOF
	}
	count := len(b)
	if int64(count) > p.size-off {
		b = b[:p.size-off]
	}
	n, err := p.Reader.ReadAt(b, p.off+off)
	if n < count && err == nil {
		err = io.EOF
	}
	return n, err
}
func Open(r storage.Reader) ([]Entry, error) {
	if r == nil || r.Size() < 26 {
		return nil, fmt.Errorf("appledouble: truncated header")
	}
	h := make([]byte, 26)
	if _, err := io.ReadFull(io.NewSectionReader(r, 0, 26), h); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if be.Uint32(h) != 0x00051607 || be.Uint32(h[4:]) != 0x00020000 {
		return nil, fmt.Errorf("appledouble: expected version2 AppleDouble")
	}
	count := int(be.Uint16(h[24:]))
	if count > 256 || int64(26+count*12) > r.Size() {
		return nil, fmt.Errorf("appledouble: entry table bounds")
	}
	table := make([]byte, count*12)
	if _, err := io.ReadFull(io.NewSectionReader(r, 26, int64(len(table))), table); err != nil {
		return nil, err
	}
	type span struct{ off, end uint64 }
	var spans []span
	ids := map[uint32]bool{}
	var entries []Entry
	for i := 0; i < count; i++ {
		e := table[i*12:]
		id := be.Uint32(e)
		off, size := uint64(be.Uint32(e[4:])), uint64(be.Uint32(e[8:]))
		if ids[id] || off < uint64(26+len(table)) || off > uint64(r.Size()) || size > uint64(r.Size())-off {
			return nil, fmt.Errorf("appledouble: invalid/duplicate extent")
		}
		for _, s := range spans {
			if size > 0 && off < s.end && s.off < off+size {
				return nil, fmt.Errorf("appledouble: overlapping entries")
			}
		}
		ids[id] = true
		spans = append(spans, span{off, off + size})
		entries = append(entries, Entry{id, part{r, int64(off), int64(size)}})
	}
	return entries, nil
}
