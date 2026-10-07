// Package lzfse decodes Apple's LZFSE/LZVN block streams as portable file views.
// Derived from Apple's BSD-licensed reference algorithm; see NOTICE.
package lzfse

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
	"math"
	"math/bits"
	"sort"
	"sync"
)

const MaxBlock = 64 << 20
const MaxBlocks = 100000
const historySize = 262144

var le = binary.LittleEndian

type block struct {
	kind                                                                string
	off, packed, start, size                                            int64
	literals, matches, literalBytes, matchBytes, literalBits, matchBits int
	states                                                              [7]int
	freq                                                                [360]uint16
}
type cached struct {
	data []byte
	tick uint64
}
type File struct {
	source  storage.Reader
	size    int64
	blocks  []block
	mu      sync.Mutex
	next    int
	history []byte
	cache   map[int]cached
	cached  int
	tick    uint64
}

func (f *File) Size() int64 { return f.size }
func read(r storage.Reader, off, n int64) ([]byte, error) {
	if off < 0 || n < 0 || n > MaxBlock || off > r.Size() || n > r.Size()-off {
		return nil, fmt.Errorf("lzfse: invalid source extent")
	}
	b := make([]byte, int(n))
	_, err := io.ReadFull(io.NewSectionReader(r, off, n), b)
	return b, err
}
func Open(source storage.Reader, maximum int64) (*File, error) {
	if source == nil || maximum < 0 {
		return nil, fmt.Errorf("lzfse: invalid source/maximum")
	}
	if maximum == 0 {
		maximum = math.MaxInt64
	}
	f := &File{source: source, cache: map[int]cached{}}
	off := int64(0)
	for {
		sig, err := read(source, off, 4)
		if err != nil {
			return nil, err
		}
		if string(sig) == "bvx$" {
			if off+4 != source.Size() {
				return nil, fmt.Errorf("lzfse: trailing data")
			}
			return f, nil
		}
		if len(f.blocks) >= MaxBlocks {
			return nil, fmt.Errorf("lzfse: block count exceeded")
		}
		h, err := read(source, off, 8)
		if err != nil {
			return nil, err
		}
		b := block{kind: string(sig), size: int64(le.Uint32(h[4:])), start: f.size}
		header := int64(8)
		switch b.kind {
		case "bvx-":
			b.packed = b.size
		case "bvxn":
			h, err = read(source, off, 12)
			header = 12
			if err != nil {
				return nil, err
			}
			b.packed = int64(le.Uint32(h[8:]))
		case "bvx1":
			h, err = read(source, off, 772)
			header = 772
			if err != nil {
				return nil, err
			}
			b.packed = int64(le.Uint32(h[8:]))
			b.literals = int(le.Uint32(h[12:]))
			b.matches = int(le.Uint32(h[16:]))
			b.literalBytes = int(le.Uint32(h[20:]))
			b.matchBytes = int(le.Uint32(h[24:]))
			b.literalBits = int(int32(le.Uint32(h[28:])))
			b.matchBits = int(int32(le.Uint32(h[40:])))
			for i := 0; i < 4; i++ {
				b.states[i] = int(le.Uint16(h[32+2*i:]))
			}
			for i := 0; i < 3; i++ {
				b.states[4+i] = int(le.Uint16(h[44+2*i:]))
			}
			for i := range b.freq {
				b.freq[i] = le.Uint16(h[50+2*i:])
			}
		case "bvx2":
			h, err = read(source, off, 32)
			if err != nil {
				return nil, err
			}
			a, c, d := le.Uint64(h[8:]), le.Uint64(h[16:]), le.Uint64(h[24:])
			header = int64(uint32(d))
			if header < 32 || header > 752 {
				return nil, fmt.Errorf("lzfse: invalid v2 header size")
			}
			b.literals = int(a & 0xfffff)
			b.literalBytes = int((a >> 20) & 0xfffff)
			b.matches = int((a >> 40) & 0xfffff)
			b.literalBits = int((a>>60)&7) - 7
			b.matchBytes = int((c >> 40) & 0xfffff)
			b.matchBits = int((c>>60)&7) - 7
			b.packed = int64(b.literalBytes + b.matchBytes)
			for i := 0; i < 4; i++ {
				b.states[i] = int((c >> uint(i*10)) & 1023)
			}
			for i := 0; i < 3; i++ {
				b.states[4+i] = int((d >> uint(32+10*i)) & 1023)
			}
			h, err = read(source, off+32, header-32)
			if err != nil {
				return nil, err
			}
			if err = frequencies(h, b.freq[:]); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("lzfse: unsupported block %q", b.kind)
		}
		if b.size <= 0 || b.size > MaxBlock || b.packed <= 0 || b.packed > MaxBlock || b.size > maximum-f.size {
			return nil, fmt.Errorf("lzfse: invalid block bounds")
		}
		if b.kind == "bvx1" || b.kind == "bvx2" {
			if b.literals < 0 || b.literals > 40000 || b.literals%4 != 0 || b.matches < 0 || b.matches > 10000 || b.literalBytes < 0 || b.matchBytes < 0 || int64(b.literalBytes+b.matchBytes) != b.packed || b.literalBits < -7 || b.literalBits > 0 || b.matchBits < -7 || b.matchBits > 0 {
				return nil, fmt.Errorf("lzfse: invalid entropy header")
			}
		}
		b.off = off + header
		if b.off > source.Size() || b.packed > source.Size()-b.off {
			return nil, fmt.Errorf("lzfse: truncated block")
		}
		f.blocks = append(f.blocks, b)
		f.size += b.size
		off = b.off + b.packed
	}
}
func frequencies(src []byte, dst []uint16) error {
	if len(src) == 0 {
		return fmt.Errorf("lzfse: missing frequency table")
	}
	widths := [32]int{2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14}
	values := [32]int{0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1, 0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1}
	var acc uint32
	pos, n := 0, 0
	for i := range dst {
		for pos < len(src) && n <= 24 {
			acc |= uint32(src[pos]) << uint(n)
			n += 8
			pos++
		}
		width := widths[acc&31]
		if width > n {
			return fmt.Errorf("lzfse: truncated frequency table")
		}
		value := values[acc&31]
		if width == 8 {
			value = 8 + int((acc>>4)&15)
		}
		if width == 14 {
			value = 24 + int((acc>>4)&1023)
		}
		dst[i] = uint16(value)
		acc >>= uint(width)
		n -= width
	}
	if pos != len(src) || n >= 8 || acc != 0 {
		return fmt.Errorf("lzfse: trailing frequency bits")
	}
	return nil
}

type reverseBits struct {
	data []byte
	end  int
	err  error
}

func reverse(data []byte, padding int) *reverseBits {
	r := &reverseBits{data: data, end: len(data)*8 + padding}
	if padding < -7 || padding > 0 || r.end < 0 || len(data) > 0 && padding != 0 && data[len(data)-1]>>uint(8+padding) != 0 {
		r.err = fmt.Errorf("lzfse: invalid entropy padding")
	}
	return r
}
func (r *reverseBits) take(n int) int {
	if r.err != nil {
		return 0
	}
	if n < 0 || n > 32 || n > r.end {
		r.err = fmt.Errorf("lzfse: truncated entropy stream")
		return 0
	}
	r.end -= n
	var v uint64
	start := r.end / 8
	count := (r.end%8 + n + 7) / 8
	for i := 0; i < count; i++ {
		v |= uint64(r.data[start+i]) << uint(8*i)
	}
	return int((v >> uint(r.end%8)) & ((uint64(1) << uint(n)) - 1))
}

type stateEntry struct {
	width, delta, value, extra int
	valid                      bool
}

func table(freq []uint16, states int, extra, base []int) ([]stateEntry, error) {
	t := make([]stateEntry, states)
	pos := 0
	for symbol, count := range freq {
		f := int(count)
		if f == 0 {
			continue
		}
		if f > states-pos {
			return nil, fmt.Errorf("lzfse: invalid frequencies")
		}
		k := bits.Len(uint(states)) - bits.Len(uint(f))
		j0 := ((2 * states) >> uint(k)) - f
		for j := 0; j < f; j++ {
			e := stateEntry{value: symbol, valid: true}
			if j < j0 {
				e.width = k
				e.delta = ((f + j) << uint(k)) - states
			} else {
				e.width = k - 1
				e.delta = (j - j0) << uint(k-1)
			}
			if extra != nil {
				e.extra = extra[symbol]
				e.value = base[symbol]
			}
			t[pos] = e
			pos++
		}
	}
	return t, nil
}
func symbol(t []stateEntry, state *int, r *reverseBits) int {
	if *state < 0 || *state >= len(t) || !t[*state].valid {
		r.err = fmt.Errorf("lzfse: invalid entropy state")
		return 0
	}
	e := t[*state]
	v := r.take(e.width + e.extra)
	*state = e.delta + (v >> uint(e.extra))
	return e.value + (v & ((1 << uint(e.extra)) - 1))
}

var lExtra = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8}
var lBase = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60}
var mExtra = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11}
var mBase = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312}

func distances() ([]int, []int) {
	extra, base := make([]int, 64), make([]int, 64)
	for i := 0; i < 4; i++ {
		base[i] = i
	}
	current := 4
	for i := 4; i < 64; i++ {
		extra[i] = i / 4
		base[i] = current
		current += 1 << uint(extra[i])
	}
	return extra, base
}
func decode(b block, src, history []byte) ([]byte, error) {
	if b.kind == "bvx-" {
		return src, nil
	}
	if b.kind == "bvxn" {
		return decodeLZVN(src, int(b.size), history)
	}
	lt, err := table(b.freq[104:], 1024, nil, nil)
	if err != nil {
		return nil, err
	}
	l, err := table(b.freq[:20], 64, lExtra, lBase)
	if err != nil {
		return nil, err
	}
	m, err := table(b.freq[20:40], 64, mExtra, mBase)
	if err != nil {
		return nil, err
	}
	de, db := distances()
	d, err := table(b.freq[40:104], 256, de, db)
	if err != nil {
		return nil, err
	}
	literals := make([]byte, b.literals)
	r := reverse(src[:b.literalBytes], b.literalBits)
	states := b.states
	for i := range literals {
		literals[i] = byte(symbol(lt, &states[i%4], r))
	}
	if r.err != nil {
		return nil, r.err
	}
	r = reverse(src[b.literalBytes:], b.matchBits)
	out := make([]byte, 0, int(b.size))
	literal := 0
	distance := -1
	for i := 0; i < b.matches; i++ {
		length := symbol(l, &states[4], r)
		match := symbol(m, &states[5], r)
		newDistance := symbol(d, &states[6], r)
		if r.err != nil {
			return nil, r.err
		}
		if newDistance != 0 {
			distance = newDistance
		}
		if length > len(literals)-literal || length+match > int(b.size)-len(out) {
			return nil, fmt.Errorf("lzfse: literal/output overflow")
		}
		out = append(out, literals[literal:literal+length]...)
		literal += length
		if match > 0 && (distance <= 0 || distance > len(history)+len(out)) {
			return nil, fmt.Errorf("lzfse: invalid match distance")
		}
		for j := 0; j < match; j++ {
			index := len(out) - distance
			if index < 0 {
				out = append(out, history[len(history)+index])
			} else {
				out = append(out, out[index])
			}
		}
	}
	if int64(len(out)) != b.size {
		return nil, fmt.Errorf("lzfse: decoded length mismatch")
	}
	return out, nil
}
func (f *File) retain(i int, data []byte) {
	for f.cached+len(data) > MaxBlock {
		oldest := -1
		for key, c := range f.cache {
			if oldest < 0 || c.tick < f.cache[oldest].tick {
				oldest = key
			}
		}
		if oldest < 0 {
			break
		}
		f.cached -= len(f.cache[oldest].data)
		delete(f.cache, oldest)
	}
	if previous, ok := f.cache[i]; ok {
		f.cached -= len(previous.data)
	}
	f.tick++
	f.cache[i] = cached{data, f.tick}
	f.cached += len(data)
}
func (f *File) chunk(i int) ([]byte, error) {
	if c, ok := f.cache[i]; ok {
		f.tick++
		c.tick = f.tick
		f.cache[i] = c
		return c.data, nil
	}
	if i < f.next {
		f.next = 0
		f.history = nil
	}
	for f.next <= i {
		b := f.blocks[f.next]
		src, err := read(f.source, b.off, b.packed)
		if err != nil {
			return nil, err
		}
		data, err := decode(b, src, f.history)
		if err != nil {
			return nil, fmt.Errorf("lzfse: block %d: %w", f.next, err)
		}
		if len(data) >= historySize {
			f.history = append(f.history[:0], data[len(data)-historySize:]...)
		} else {
			keep := min(len(f.history), historySize-len(data))
			f.history = append(append([]byte(nil), f.history[len(f.history)-keep:]...), data...)
		}
		f.retain(f.next, data)
		f.next++
	}
	return f.cache[i].data, nil
}
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if off < 0 {
		return 0, fmt.Errorf("lzfse: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.size {
		return 0, io.EOF
	}
	wanted := len(p)
	done := 0
	i := sort.Search(len(f.blocks), func(i int) bool { return f.blocks[i].start+f.blocks[i].size > off })
	for len(p) > 0 && i < len(f.blocks) {
		b := f.blocks[i]
		data, err := f.chunk(i)
		if err != nil {
			return done, err
		}
		n := copy(p, data[off-b.start:])
		p = p[n:]
		off += int64(n)
		done += n
		i++
	}
	if done != wanted {
		return done, io.EOF
	}
	return done, nil
}
