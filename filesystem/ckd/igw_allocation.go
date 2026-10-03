package ckd

import (
	"bytes"
	"fmt"
	"sort"
)

// objectAllocation joins type-7003 attributes by the logical-page selector in
// key bytes 16..19. A continued allocation is not an implicit sparse tail.
// Gaps and overlaps fail explicitly; holes inside observed E5 directories are
// handled by the qualified single-record allocation decoder.
func (g *IGW) objectAllocation(attrs map[[20]byte][]byte, namespace uint64, object [6]byte, holes bool) (*Content, error) {
	prefix := igwKey(namespace, object, 0x7003)
	type part struct {
		page  uint32
		value []byte
	}
	var parts []part
	for key, value := range attrs {
		if bytes.Equal(key[:16], prefix[:16]) {
			parts = append(parts, part{be.Uint32(key[16:]), value})
		}
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("IGW: missing object allocation")
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].page < parts[j].page })
	out := &Content{source: g.source}
	for _, p := range parts {
		if int64(p.page)*4096 != out.size {
			return nil, fmt.Errorf("IGW: sparse or overlapping allocation selector")
		}
		data, err := g.allocation(p.value, holes)
		if err != nil {
			return nil, err
		}
		if data.Size() == 0 && len(parts) > 1 {
			return nil, fmt.Errorf("IGW: empty continuation allocation")
		}
		for _, s := range data.spans {
			s.start += out.size
			out.spans = append(out.spans, s)
		}
		out.size += data.Size()
	}
	return out, nil
}
