package ziparchive

import (
	"archive/zip"
	"bufio"
	"fmt"
	"hash/crc32"
	"io"
)

// Legacy ZIP codecs are streaming and keep fixed-size dictionaries. No global
// archive/zip decompressor registration is used: Implode's flags belong to the
// individual member. The normal Entry window supplies bounded random access.
// Algorithm references are recorded in docs/third-party-format-references.md.
type zipBits struct {
	r    *bufio.Reader
	bits uint32
	n    uint
}

func (b *zipBits) get(n uint) (int, error) {
	for b.n < n {
		v, e := b.r.ReadByte()
		if e != nil {
			if e == io.EOF {
				e = io.ErrUnexpectedEOF
			}
			return 0, e
		}
		b.bits |= uint32(v) << b.n
		b.n += 8
	}
	v := int(b.bits & ((1 << n) - 1))
	b.bits >>= n
	b.n -= n
	return v, nil
}

type legacyDecoder interface{ next() ([]byte, error) }
type legacyReader struct {
	decoder      legacyDecoder
	bits         *zipBits
	pending      []byte
	left         uint64
	crc, wantCRC uint32
	err          error
}

func (r *legacyReader) Close() error { return nil }
func (r *legacyReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := 0
	for n < len(p) {
		if r.err != nil {
			return n, r.err
		}
		if len(r.pending) == 0 {
			if r.left == 0 {
				// Only sub-byte padding may follow the final symbol.
				_, e := r.bits.r.ReadByte()
				if e != io.EOF {
					if e == nil {
						e = zip.ErrFormat
					}
					r.err = e
				} else if r.crc != r.wantCRC {
					r.err = zip.ErrChecksum
				} else {
					r.err = io.EOF
				}
				return n, r.err
			}
			block, e := r.decoder.next()
			if e != nil {
				r.err = e
				return n, e
			}
			if len(block) == 0 || uint64(len(block)) > r.left {
				r.err = fmt.Errorf("zip: invalid legacy output length")
				return n, r.err
			}
			r.pending = block
		}
		k := copy(p[n:], r.pending)
		r.crc = crc32.Update(r.crc, crc32.IEEETable, r.pending[:k])
		r.left -= uint64(k)
		r.pending = r.pending[k:]
		n += k
	}
	return n, nil
}
func (f *Entry) open() (io.ReadCloser, error) {
	if f.entry.Method != 1 && f.entry.Method != 6 {
		return f.entry.Open()
	}
	if f.entry.Flags&(1|64) != 0 {
		return nil, fmt.Errorf("zip: encrypted legacy member is unsupported")
	}
	raw, err := f.entry.OpenRaw()
	if err != nil {
		return nil, err
	}
	b := &zipBits{r: bufio.NewReader(raw)}
	var d legacyDecoder
	if f.entry.Method == 1 {
		s := &shrinkDecoder{bits: b, width: 9, free: 257, old: -1}
		for i := 0; i < 256; i++ {
			s.used[i] = true
			s.value[i] = byte(i)
			s.parent[i] = -1
		}
		d = s
	} else {
		e := &implodeDecoder{bits: b, low: 6, minimum: 2}
		if f.entry.Flags&2 != 0 {
			e.low = 7
		}
		if f.entry.Flags&4 != 0 {
			e.minimum = 3
			e.coded = true
			if err = e.literal.load(b, 256); err != nil {
				return nil, err
			}
		}
		if err = e.length.load(b, 64); err != nil {
			return nil, err
		}
		if err = e.distance.load(b, 64); err != nil {
			return nil, err
		}
		d = e
	}
	return &legacyReader{decoder: d, bits: b, left: f.entry.UncompressedSize64, wantCRC: f.entry.CRC32}, nil
}

// Implode uses complemented canonical Shannon-Fano codes. Trees contain a
// run-length encoded code length for every symbol; all lengths are 1..16.
type implodeTree struct {
	count   [17]int
	symbols [256]int
}

func (t *implodeTree) load(b *zipBits, symbols int) error {
	runs, e := b.get(8)
	if e != nil {
		return e
	}
	runs++
	var lengths [256]int
	pos := 0
	for i := 0; i < runs; i++ {
		v, e := b.get(8)
		if e != nil {
			return e
		}
		count, length := (v>>4)+1, (v&15)+1
		if count > symbols-pos {
			return fmt.Errorf("zip implode: tree run overflow")
		}
		for j := 0; j < count; j++ {
			lengths[pos] = length
			pos++
			t.count[length]++
		}
	}
	if pos != symbols {
		return fmt.Errorf("zip implode: incomplete tree lengths")
	}
	left := 1
	var offset [17]int
	for i := 1; i <= 16; i++ {
		left = left*2 - t.count[i]
		if left < 0 {
			return fmt.Errorf("zip implode: oversubscribed tree")
		}
		if i > 1 {
			offset[i] = offset[i-1] + t.count[i-1]
		}
	}
	if left != 0 {
		return fmt.Errorf("zip implode: incomplete tree")
	}
	for symbol := 0; symbol < symbols; symbol++ {
		l := lengths[symbol]
		t.symbols[offset[l]] = symbol
		offset[l]++
	}
	return nil
}
func (t *implodeTree) read(b *zipBits) (int, error) {
	code, first, index := 0, 0, 0
	for length := 1; length <= 16; length++ {
		bit, e := b.get(1)
		if e != nil {
			return 0, e
		}
		code = code<<1 | (bit ^ 1)
		count := t.count[length]
		if code >= first && code-first < count {
			return t.symbols[index+code-first], nil
		}
		index += count
		first = (first + count) << 1
	}
	return 0, fmt.Errorf("zip implode: invalid code")
}

type implodeDecoder struct {
	bits                      *zipBits
	literal, length, distance implodeTree
	low                       uint
	minimum                   int
	coded                     bool
	history                   [8192]byte
	pos                       int
	block                     [321]byte
}

func (d *implodeDecoder) next() ([]byte, error) {
	tag, e := d.bits.get(1)
	if e != nil {
		return nil, e
	}
	if tag != 0 {
		var v int
		if d.coded {
			v, e = d.literal.read(d.bits)
		} else {
			v, e = d.bits.get(8)
		}
		if e != nil {
			return nil, e
		}
		d.history[d.pos] = byte(v)
		d.pos = (d.pos + 1) & 8191
		d.block[0] = byte(v)
		return d.block[:1], nil
	}
	low, e := d.bits.get(d.low)
	if e != nil {
		return nil, e
	}
	high, e := d.distance.read(d.bits)
	if e != nil {
		return nil, e
	}
	distance := (high<<d.low | low) + 1
	length, e := d.length.read(d.bits)
	if e != nil {
		return nil, e
	}
	if length == 63 {
		extra, e := d.bits.get(8)
		if e != nil {
			return nil, e
		}
		length += extra
	}
	length += d.minimum
	// References before the beginning of the output address the zero-initialized
	// dictionary. Overlapping matches intentionally read bytes just written.
	for i := 0; i < length; i++ {
		v := d.history[(d.pos-distance)&8191]
		d.history[d.pos] = v
		d.pos = (d.pos + 1) & 8191
		d.block[i] = v
	}
	return d.block[:length], nil
}

type shrinkDecoder struct {
	bits      *zipBits
	width     uint
	free, old int
	parent    [8192]int
	value     [8192]byte
	used      [8192]bool
	stack     [8193]byte
	first     byte
}

func (d *shrinkDecoder) clearLeaves() {
	var parent [8192]bool
	for i := 257; i < 8192; i++ {
		if d.used[i] && d.parent[i] >= 257 {
			parent[d.parent[i]] = true
		}
	}
	for i := 257; i < 8192; i++ {
		if !parent[i] {
			d.used[i] = false
		}
	}
	d.free = 257
}
func (d *shrinkDecoder) next() ([]byte, error) {
	for {
		code, e := d.bits.get(d.width)
		if e != nil {
			return nil, e
		}
		if code == 256 {
			sub, e := d.bits.get(d.width)
			if e != nil {
				return nil, e
			}
			switch sub {
			case 1:
				if d.width == 13 {
					return nil, fmt.Errorf("zip shrink: excessive code width")
				}
				d.width++
			case 2:
				d.clearLeaves()
			default:
				return nil, fmt.Errorf("zip shrink: invalid control %d", sub)
			}
			continue
		}
		for d.free < 8192 && d.used[d.free] {
			d.free++
		}
		cur, pos := code, len(d.stack)
		if !d.used[code] {
			if d.old < 0 || code != d.free {
				return nil, fmt.Errorf("zip shrink: undefined code %d", code)
			}
			pos--
			d.stack[pos] = d.first
			cur = d.old
		}
		for cur >= 256 {
			if cur == 256 || cur >= 8192 || !d.used[cur] || pos == 0 {
				return nil, fmt.Errorf("zip shrink: invalid prefix chain")
			}
			pos--
			d.stack[pos] = d.value[cur]
			cur = d.parent[cur]
		}
		if cur < 0 || pos == 0 {
			return nil, fmt.Errorf("zip shrink: invalid root")
		}
		pos--
		d.stack[pos] = byte(cur)
		first := d.stack[pos]
		if d.old >= 0 && d.free < 8192 {
			// A partial clear can free the previous leaf. Do not permit a dangling
			// parent to become a silently valid string when that slot is reused.
			if !d.used[d.old] {
				return nil, fmt.Errorf("zip shrink: cleared previous code")
			}
			d.parent[d.free] = d.old
			d.value[d.free] = first
			d.used[d.free] = true
			d.free++
		}
		d.old = code
		d.first = first
		return d.stack[pos:], nil
	}
}
