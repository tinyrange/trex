// Package ibmidasd inspects IBM i DASD page envelopes and their SLS addresses.
// An index is an observation of explicitly supplied physical ranges, not an
// authoritative filesystem allocation map. Duplicate addresses remain visible.
package ibmidasd

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/tinyrange/trex/binary/issi"
	"github.com/tinyrange/trex/storage"
)

const PageBytes = 4096
const FrameBytes = 4608

// VirtualAddress decodes a page's virtual address. The address is
// distributed across eight headers so pointer tags may occupy other bits.
// A false result means the headers do not identify an ordinary SLS page; it
// does not establish corruption (compressed and control headers also exist).
func VirtualAddress(h []byte) (uint64, bool) {
	if len(h) != 64 || (h[0]>>2)&3 == 3 {
		return 0, false
	}
	v := uint64(h[8]>>2)<<58 | uint64(binary.BigEndian.Uint16(h[8:])&1023)<<48 |
		uint64(h[10])<<40 | uint64(h[16]>>2)<<34 | uint64(h[24]>>2)<<28 |
		uint64(h[32]&0xfc)<<20 | uint64(h[40]&0xfc)<<14 | uint64(h[48]&0xf0)<<8
	const scope = uint64(1023) << 48
	const low = uint64(0xfffffff000)
	for i := 0; i < 8; i++ {
		word := binary.BigEndian.Uint64(h[i*8:])
		if word&scope != v&scope || h[i*8+7]&8 == 0 && word&low != v&low {
			return 0, false
		}
	}
	return v, v != 0
}

type Range struct{ Offset, Size int64 }

type Index struct {
	Source            storage.Reader
	Pages             map[uint64][]int64
	Scanned, Unmapped int64
}

// PageAddress reads the header of a physical frame directly. It also works
// outside the ranges originally indexed and does not change the index.
func (idx *Index) PageAddress(offset int64) (uint64, bool, error) {
	if offset < 0 || offset%FrameBytes != 0 || offset > idx.Source.Size()-FrameBytes {
		return 0, false, fmt.Errorf("ibmi dasd: invalid physical frame offset %d", offset)
	}
	var headers [64]byte
	if _, err := readFullAt(idx.Source, headers[:], offset+PageBytes+8); err != nil {
		return 0, false, err
	}
	address, ok := VirtualAddress(headers[:])
	return address, ok, nil
}

// Open indexes complete 9-sector frames intersecting the supplied ranges.
// Ranges may describe allocated extents of a sparse device. Omitted ranges
// are not examined or assumed empty. Bounds/budgets are checked before I/O.
func Open(source storage.Reader, ranges []Range, maximum int64) (*Index, error) {
	if source == nil || source.Size() < 0 || maximum < 1 || maximum > 1<<24 || len(ranges) > 65536 {
		return nil, fmt.Errorf("ibmi dasd: invalid source or budget")
	}
	ranges = append([]Range(nil), ranges...)
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].Offset < ranges[j].Offset })
	var count, last int64
	last = -1
	for n, r := range ranges {
		if r.Offset < 0 || r.Size < 0 || r.Offset > source.Size() || r.Size > source.Size()-r.Offset || n > 0 && r.Offset < ranges[n-1].Offset+ranges[n-1].Size {
			return nil, fmt.Errorf("ibmi dasd: invalid or overlapping range")
		}
		if r.Size == 0 {
			continue
		}
		first, end := r.Offset/FrameBytes, min((r.Offset+r.Size-1)/FrameBytes+1, source.Size()/FrameBytes)
		first = max(first, last+1)
		if end > first {
			count += end - first
			last = end - 1
		}
		if count > maximum {
			return nil, fmt.Errorf("ibmi dasd: page budget")
		}
	}
	idx := &Index{Source: source, Pages: make(map[uint64][]int64)}
	last = -1
	var sidecar [512]byte
	for _, r := range ranges {
		if r.Size == 0 {
			continue
		}
		first, end := max(r.Offset/FrameBytes, last+1), min((r.Offset+r.Size-1)/FrameBytes+1, source.Size()/FrameBytes)
		for page := first; page < end; page++ {
			offset := page * FrameBytes
			if _, err := readFullAt(source, sidecar[:], offset+PageBytes); err != nil {
				return nil, err
			}
			idx.Scanned++
			if address, ok := VirtualAddress(sidecar[8:72]); ok {
				idx.Pages[address] = append(idx.Pages[address], offset)
			} else {
				idx.Unmapped++
			}
			last = page
		}
	}
	return idx, nil
}

// VirtualFile borrows uniquely identified SLS pages. It never supplies zeros
// for absent pages or chooses among duplicate physical versions.
func (idx *Index) VirtualFile(address uint64, size int64) (storage.Reader, error) {
	if size < 0 || size > 1<<31 || uint64(size) > ^uint64(0)-address {
		return nil, fmt.Errorf("ibmi dasd: invalid virtual range")
	}
	if size != 0 {
		first, last := address/4096, (address+uint64(size)-1)/4096
		for page := first; page <= last; page++ {
			if n := len(idx.Pages[page*4096]); n != 1 {
				return nil, fmt.Errorf("ibmi dasd: virtual page %016x has %d physical matches", page*4096, n)
			}
		}
	}
	return &virtualReader{index: idx, address: address, size: size}, nil
}

type virtualReader struct {
	index   *Index
	address uint64
	size    int64
}

func (v *virtualReader) Size() int64 { return v.size }
func (v *virtualReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ibmi dasd: negative read offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= v.size {
		return 0, io.EOF
	}
	wanted := len(p)
	p = p[:min(int64(len(p)), v.size-off)]
	total := 0
	for len(p) > 0 {
		address := v.address + uint64(off)
		offset := v.index.Pages[address&^4095][0]
		page, _ := Page(v.index.Source, offset)
		count := min(len(p), 4096-int(address%4096))
		n, err := page.ReadAt(p[:count], int64(address%4096))
		total += n
		if err != nil {
			return total, err
		}
		p = p[count:]
		off += int64(count)
	}
	if total < wanted {
		return total, io.EOF
	}
	return total, nil
}

func readFullAt(r io.ReaderAt, p []byte, off int64) (int, error) {
	n, err := r.ReadAt(p, off)
	if n != len(p) && err == nil {
		err = io.ErrUnexpectedEOF
	}
	if n == len(p) && err == io.EOF {
		err = nil
	}
	return n, err
}

// Page returns an independent lazy reader for a complete envelope. A nonzero
// stamp must agree in all ten locations before restoring displaced words.
// Unstamped envelopes expose stored data unchanged; no checksum is claimed.
func Page(source storage.Reader, offset int64) (storage.Reader, error) {
	if source == nil || offset < 0 || offset%FrameBytes != 0 || offset > source.Size() || FrameBytes > source.Size()-offset {
		return nil, fmt.Errorf("ibmi dasd: invalid page offset")
	}
	return &pageReader{source: source, offset: offset}, nil
}

type pageReader struct {
	source storage.Reader
	offset int64
}

func (*pageReader) Size() int64 { return PageBytes }
func (p *pageReader) ReadAt(dst []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ibmi dasd: negative read offset")
	}
	if len(dst) == 0 {
		return 0, nil
	}
	if off >= PageBytes {
		return 0, io.EOF
	}
	var frame [FrameBytes]byte
	if _, err := readFullAt(p.source, frame[:], p.offset); err != nil {
		return 0, err
	}
	sidecar, data := frame[PageBytes:], frame[:PageBytes]
	stamp := binary.BigEndian.Uint64(sidecar)
	if binary.BigEndian.Uint64(sidecar[504:]) != stamp {
		return 0, fmt.Errorf("ibmi dasd: mismatched sidecar controls")
	}
	if stamp != 0 {
		for i := 0; i < 8; i++ {
			if binary.BigEndian.Uint64(data[i*512+504:]) != stamp {
				return 0, fmt.Errorf("ibmi dasd: mismatched sector control %d", i)
			}
		}
		var headers [64]byte
		if err := issi.Restore(sidecar, headers[:], data, false); err != nil {
			return 0, err
		}
	}
	n := copy(dst, data[off:])
	if n < len(dst) {
		return n, io.EOF
	}
	return n, nil
}
