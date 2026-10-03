package ckd

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/storage"
)

// OpenStoredProgramObject preserves the actual stored IEWPLMH file. The PLMH
// size field is not stored EOF: independently sized Unix program files contain
// packed objects with a larger declared size. PDSE callers must establish EOF
// from the member storage descriptor, not synthesize bytes to match that field.
// OpenProgramObject is the separate, optional gap-expanded image view.
func OpenStoredProgramObject(source storage.Reader) (*Content, error) {
	if source == nil || source.Size() < 24 {
		return nil, fmt.Errorf("PDSE stored program: short header")
	}
	h := make([]byte, 24)
	if _, e := source.ReadAt(h, 0); e != nil {
		return nil, e
	}
	if !bytes.Equal(h[:8], []byte{0xc9, 0xc5, 0xe6, 0xd7, 0xd3, 0xd4, 0xc8, 0x40}) || h[12] < 2 || h[12] > 5 {
		return nil, fmt.Errorf("PDSE stored program: unsupported header")
	}
	declared := int64(be.Uint32(h[16:]))
	count := int64(be.Uint32(h[20:]))
	if declared < source.Size() || count < 1 || count > 256 || int64(be.Uint32(h[8:])) != 24+12*count || 24+12*count > source.Size() {
		return nil, fmt.Errorf("PDSE stored program: invalid declared geometry")
	}
	table := make([]byte, count*12)
	if _, e := source.ReadAt(table, 24); e != nil {
		return nil, e
	}
	seen := map[uint16]bool{}
	for i := int64(0); i < count; i++ {
		s := table[i*12:]
		kind := be.Uint16(s)
		off, size := int64(be.Uint32(s[4:])), int64(be.Uint32(s[8:]))
		if kind == 0 || seen[kind] || off > declared || size > declared-off {
			return nil, fmt.Errorf("PDSE stored program: invalid section")
		}
		seen[kind] = true
		// Definition and loader metadata precede any packed text ranges.
		if kind <= 6 && (off > source.Size() || size > source.Size()-off) {
			return nil, fmt.Errorf("PDSE stored program: truncated metadata")
		}
	}
	return &Content{source: source, size: source.Size(), spans: []span{{0, source.Size(), 0}}}, nil
}
