package floppy

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

// OpenSaveDskF reads IBM SaveDskF's AA58/AA59 sector images and AA5A
// compressed images. The checksum covers the recorded sectors, not the header.
// Unrecorded tail sectors remain missing; their original contents are unknown.
func OpenSaveDskF(r storage.Reader) (*File, error) {
	h, err := read(r, 0, 40)
	if err != nil {
		return nil, err
	}
	if h[0] != 0xaa || h[1] < 0x58 || h[1] > 0x5a {
		return nil, fmt.Errorf("savedskf: invalid signature")
	}
	cyl, heads, sectors := u16(h[24:]), u16(h[26:]), u16(h[28:])
	stored := u16(h[34:])
	offset := u16(h[38:])
	if offset == 0 {
		offset = 512
	}
	if u16(h[4:]) != 512 || cyl < 1 || cyl > 84 || heads < 1 || heads > 2 || sectors < 1 || sectors > 40 {
		return nil, fmt.Errorf("savedskf: unsupported geometry")
	}
	total := cyl * heads * sectors
	if stored < 1 || stored > total || offset < 40 || int64(offset) > r.Size() {
		return nil, fmt.Errorf("savedskf: invalid recorded sector count or data offset")
	}
	comment := u16(h[36:])
	if comment != 0 && (comment < 40 || comment > offset) {
		return nil, fmt.Errorf("savedskf: invalid comment offset")
	}
	size := stored * 512
	var data []byte
	if h[1] == 0x5a {
		data, err = decodeIBMLZW(io.NewSectionReader(r, int64(offset), r.Size()-int64(offset)), size)
	} else {
		data, err = read(r, int64(offset), size)
	}
	if err != nil {
		return nil, fmt.Errorf("savedskf: %w", err)
	}
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(binary.LittleEndian.Uint16(data[i:]))
	}
	if want := binary.LittleEndian.Uint32(h[20:]); sum != want {
		return nil, fmt.Errorf("savedskf: checksum mismatch: got %08x, want %08x", sum, want)
	}
	f := &File{source: r, format: "savedskf", cylinders: cyl, heads: heads, sectors: sectors, unit: 512, extents: make([]extent, total)}
	for i := range f.extents {
		if i < stored {
			f.extents[i].data = data[i*512 : (i+1)*512]
		} else {
			f.extents[i].missing = true
		}
	}
	return f, nil
}

// IBM uses MSB-first, fixed 12-bit codes (1..256 are literals; 0 is EOF).
// Unlike conventional LZW, leaf entries are reused in least-recently-used
// order. Referenced parents are removed from the reuse queue until their last
// child is evicted. See docs/third-party-format-references.md for provenance.
type ibmDictionary struct {
	parent, older, newer [4096]uint16
	length, refs         [4096]uint16
	first, last          [4096]byte
	head, tail           uint16
}

func (d *ibmDictionary) unlink(c uint16) {
	p, n := d.older[c], d.newer[c]
	if p == 0 {
		d.head = n
	} else {
		d.newer[p] = n
	}
	if n == 0 {
		d.tail = p
	} else {
		d.older[n] = p
	}
	d.older[c], d.newer[c] = 0, 0
}
func (d *ibmDictionary) append(c uint16) {
	d.older[c], d.newer[c] = d.tail, 0
	if d.tail == 0 {
		d.head = c
	} else {
		d.newer[d.tail] = c
	}
	d.tail = c
}
func decodeIBMLZW(r io.Reader, size int) ([]byte, error) {
	d := new(ibmDictionary)
	for c := 1; c <= 256; c++ {
		d.first[c] = byte(c - 1)
		d.last[c] = byte(c - 1)
		d.length[c] = 1
		d.refs[c] = 1
	}
	for c := uint16(257); c < 4096; c++ {
		d.append(c)
	}
	in := bufio.NewReader(r)
	var bits uint32
	var nbits uint
	next := func() (uint16, error) {
		for nbits < 12 {
			b, e := in.ReadByte()
			if e != nil {
				if e == io.EOF {
					e = io.ErrUnexpectedEOF
				}
				return 0, e
			}
			bits = bits<<8 | uint32(b)
			nbits += 8
		}
		nbits -= 12
		code := uint16((bits >> nbits) & 4095)
		bits &= (1 << nbits) - 1
		return code, nil
	}
	out := make([]byte, 0, size)
	var old uint16
	var stack [4096]byte
	for {
		code, err := next()
		if err != nil {
			return nil, err
		}
		if code == 0 {
			if len(out) != size {
				return nil, fmt.Errorf("IBM LZW: decoded %d bytes, want %d", len(out), size)
			}
			return out, nil
		}
		if len(out) == size {
			return nil, fmt.Errorf("IBM LZW: output exceeds recorded sectors")
		}
		if old != 0 {
			slot := d.head
			if slot == 0 || slot == old || d.refs[slot] != 0 {
				return nil, fmt.Errorf("IBM LZW: invalid reuse queue")
			}
			if d.length[code] == 0 && code != slot {
				return nil, fmt.Errorf("IBM LZW: undefined code %d", code)
			}
			first := d.first[code]
			if code == slot {
				first = d.first[old]
			}
			d.unlink(slot)
			if p := d.parent[slot]; p != 0 {
				if d.refs[p] == 0 {
					return nil, fmt.Errorf("IBM LZW: invalid parent count")
				}
				d.refs[p]--
				if d.refs[p] == 0 {
					d.append(p)
				}
			}
			if d.length[old] == 0 || d.length[old] >= 3840 {
				return nil, fmt.Errorf("IBM LZW: invalid string length")
			}
			d.parent[slot] = old
			d.first[slot] = d.first[old]
			d.last[slot] = first
			d.length[slot] = d.length[old] + 1
			if d.refs[old] == 0 {
				d.unlink(old)
			}
			d.refs[old]++
			d.refs[slot] = 0
			d.append(slot)
		}
		length := int(d.length[code])
		if length == 0 || length > size-len(out) {
			return nil, fmt.Errorf("IBM LZW: invalid code or output overflow")
		}
		cur := code
		for i := length; i > 0; i-- {
			if cur == 0 || int(d.length[cur]) != i {
				return nil, fmt.Errorf("IBM LZW: invalid prefix chain")
			}
			stack[i-1] = d.last[cur]
			cur = d.parent[cur]
		}
		out = append(out, stack[:length]...)
		old = code
	}
}
