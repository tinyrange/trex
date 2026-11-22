package binary

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/tinyrange/trex/storage"
)

// TableBase is a candidate placement of a table image.
type TableBase struct {
	Base  uint64 `json:"base"`
	Hits  int    `json:"hits"`
	Total int    `json:"total"`
}

// LocateTable finds bases B at which source, placed at address B, holds a
// big-endian doubleword whose high 32 bits equal high at many of the given
// addresses. Addresses are typically slots that code is known to read
// pointers from. Candidates come from three anchor addresses spread across
// the set; those matching a quarter of a 64-address sample are scored against
// every address. All-ones doublewords are treated as fill. Positions are four-byte
// aligned relative to the source. The result is evidence of a consistent
// placement, not proof of the table's identity.
func LocateTable(source storage.Reader, addresses []uint64, high uint32, top int) ([]TableBase, error) {
	return locate(source, addresses, top, func(b []byte) bool {
		return binary.BigEndian.Uint32(b) == high && binary.BigEndian.Uint64(b) != ^uint64(0)
	})
}

// LocateWords is LocateTable for four-byte entries: an address matches when
// the big-endian word there satisfies word&mask == value (for example an
// unconditional relative branch: mask fc000003, value 48000000).
func LocateWords(source storage.Reader, addresses []uint64, mask, value uint32, top int) ([]TableBase, error) {
	return locate(source, addresses, top, func(b []byte) bool {
		return binary.BigEndian.Uint32(b)&mask == value
	})
}

func locate(source storage.Reader, addresses []uint64, top int, match func([]byte) bool) ([]TableBase, error) {
	if len(addresses) < 3 || top < 1 || top > 1000 || source.Size() > 1<<32 {
		return nil, fmt.Errorf("locate_table: need at least three addresses, top 1..1000 and a source under 4GiB")
	}
	addrs := append([]uint64(nil), addresses...)
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })
	size := source.Size()
	words := size / 4
	bits := make([]uint64, words/64+1)
	buf := make([]byte, 1<<20+4)
	for off := int64(0); off+8 <= size; off += 1 << 20 {
		n := min(int64(len(buf)), size-off)
		got, err := source.ReadAt(buf[:n], off)
		if int64(got) != n {
			if err == nil || err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		for p := int64(0); p+8 <= n && p < 1<<20; p += 4 {
			if match(buf[p : p+8]) {
				i := (off + p) / 4
				bits[i/64] |= 1 << (i % 64)
			}
		}
	}
	has := func(base, addr uint64) bool {
		p := addr - base
		if addr < base || p%4 != 0 || int64(p) < 0 || int64(p)+8 > size {
			return false
		}
		i := p / 4
		return bits[i/64]&(1<<(i%64)) != 0
	}
	a0, a1, a2 := addrs[len(addrs)/10], addrs[len(addrs)/2], addrs[len(addrs)*9/10]
	sample := make([]uint64, 0, 64)
	for i := 0; i < 64; i++ {
		sample = append(sample, addrs[i*len(addrs)/64])
	}
	seen := map[uint64]bool{}
	out := []TableBase{}
	for i := int64(0); i < words; i++ {
		if bits[i/64]&(1<<(i%64)) == 0 {
			continue
		}
		base := a0 - uint64(i*4)
		if seen[base] || !has(base, a1) || !has(base, a2) {
			continue
		}
		seen[base] = true
		sampled := 0
		for _, a := range sample {
			if has(base, a) {
				sampled++
			}
		}
		// Only placements consistent with a quarter of the sample are scored fully.
		if sampled*4 < len(sample) {
			continue
		}
		hits := 0
		for _, a := range addrs {
			if has(base, a) {
				hits++
			}
		}
		out = append(out, TableBase{Base: base, Hits: hits, Total: len(addrs)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].Base < out[j].Base
	})
	if len(out) > top {
		out = out[:top]
	}
	return out, nil
}
