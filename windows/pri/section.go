package pri

import (
	"bytes"
	"fmt"
)

// Payload validates a section's header against its TOC entry and verifies its
// trailer. It returns the interior bytes, including any format-specific padding.
// Only complete, eight-byte-aligned section extents are currently supported.
// An absent TOC entry has no payload and is reported as an error.
func (s Section) Payload() ([]byte, error) {
	d := s.Data
	if len(d) < 40 || len(d)%8 != 0 || !bytes.Equal(d[:16], s.Type[:]) ||
		uint64(le.Uint32(d[24:])) != uint64(len(d)) {
		return nil, fmt.Errorf("pri: invalid section header/extent")
	}
	// Header and TOC reorder the same metadata: u32, u16, u16 in the
	// header; u16, u16, u32 in the table entry.
	if !bytes.Equal(d[16:20], s.Metadata[4:8]) || !bytes.Equal(d[20:24], s.Metadata[:4]) {
		return nil, fmt.Errorf("pri: section metadata disagrees with table")
	}
	end := len(d) - 8
	if le.Uint32(d[end:]) != 0xdef5fade || uint64(le.Uint32(d[end+4:])) != uint64(len(d)) {
		return nil, fmt.Errorf("pri: invalid section trailer")
	}
	return d[32:end:end], nil
}
