// Package deflate provides random access to raw DEFLATE (RFC 1951) streams.
//
// A Seekable decodes forward from the nearest checkpoint: a block boundary
// recorded while decoding, holding the input bit position and the preceding
// 32 KiB window. Checkpoints are recorded lazily as decoding first passes
// through the stream, so a reader near the start of a large member never
// decodes the rest; IndexInBackground records them ahead of the reader on a
// spare core instead. Decoded pages are cached in a bounded LRU.
package deflate

import (
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"sync"
)

const (
	windowSize = 1 << 15
	fastBits   = 10
	pageSize   = 64 << 10
	maxPages   = 256 // 16 MiB of decoded pages
)

// Seekable is an io.ReaderAt over the decoded form of a raw DEFLATE stream.
type Seekable struct {
	src      io.ReaderAt
	csize    int64
	usize    int64
	interval int64

	mu    sync.Mutex // the live decoder and pages
	live  *decoder
	pages map[int64][]byte
	order []int64
	err   error

	pmu    sync.Mutex // points, which background indexing also extends
	points []checkpoint

	indexOnce sync.Once
}

// indexSlots bounds concurrent background indexing: it competes with the
// emulator for cores and with foreground reads for media bandwidth.
var indexSlots = make(chan struct{}, max(1, min(2, runtime.NumCPU()/4)))

// IndexInBackground decodes the whole stream once on another goroutine,
// recording checkpoints, so that later random reads restart near their
// target instead of decoding everything before it. Decoded data is not
// retained. Calling it again has no effect.
func (s *Seekable) IndexInBackground() {
	s.indexOnce.Do(func() {
		go func() {
			indexSlots <- struct{}{}
			defer func() { <-indexSlots }()
			d, err := s.restart(s.last())
			if err != nil {
				return
			}
			for d.skip(d.out+maxAhead) == nil {
			}
		}()
	})
}

// last returns the furthest checkpoint.
func (s *Seekable) last() checkpoint {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	return s.points[len(s.points)-1]
}

// before returns the last checkpoint at or before decoded offset off.
func (s *Seekable) before(off int64) checkpoint {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	lo, hi := 0, len(s.points)
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		if s.points[mid].out <= off {
			lo = mid
		} else {
			hi = mid
		}
	}
	return s.points[lo]
}

type checkpoint struct {
	bit    int64 // input bit offset of a block header
	out    int64 // decoded offset at that header
	window []byte
}

// NewSeekable returns random access to the size-byte decoded form of the
// compressed stream src[0:compressedSize]. interval is the decoded distance
// between checkpoints (0 selects 4 MiB).
func NewSeekable(src io.ReaderAt, compressedSize, size, interval int64) *Seekable {
	if interval <= 0 {
		interval = 4 << 20
	}
	return &Seekable{src: src, csize: compressedSize, usize: size, interval: interval,
		points: []checkpoint{{}}, pages: map[int64][]byte{}}
}

// Size returns the decoded size.
func (s *Seekable) Size() int64 { return s.usize }

// ReadAt reads decoded bytes.
func (s *Seekable) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("deflate: negative offset")
	}
	if off >= s.usize {
		return 0, io.EOF
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	n := 0
	for n < len(p) && off < s.usize {
		page, err := s.page(off / pageSize)
		if err != nil {
			s.err = err
			return n, err
		}
		c := copy(p[n:], page[off%pageSize:])
		n += c
		off += int64(c)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (s *Seekable) page(i int64) ([]byte, error) {
	if b, ok := s.pages[i]; ok {
		return b, nil
	}
	start := i * pageSize
	d := s.live
	// Continue the live decoder unless a checkpoint is closer to the page.
	if cp := s.before(start); d == nil || d.out > start || d.out < cp.out {
		var err error
		if d, err = s.restart(cp); err != nil {
			return nil, err
		}
		s.live = d
	}
	if d.out < start {
		if err := d.skip(start); err != nil {
			s.live = nil
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
	buf := make([]byte, min(pageSize, s.usize-start))
	if err := readFull(d, buf); err != nil {
		s.live = nil
		return nil, err
	}
	s.store(i, buf)
	return buf, nil
}

func readFull(d *decoder, p []byte) error {
	for n := 0; n < len(p); {
		m, err := d.read(p[n:])
		n += m
		if err != nil && n < len(p) {
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

func (s *Seekable) store(i int64, b []byte) {
	if _, ok := s.pages[i]; ok {
		return
	}
	if len(s.order) >= maxPages {
		delete(s.pages, s.order[0])
		s.order = s.order[1:]
	}
	s.pages[i] = b
	s.order = append(s.order, i)
}

func (s *Seekable) restart(cp checkpoint) (*decoder, error) {
	d := &decoder{src: s.src, csize: s.csize, seek: s}
	d.inPos = cp.bit / 8
	d.out = cp.out
	d.ring = make([]byte, ringSize)
	for i, b := range cp.window {
		d.ring[(cp.out-int64(len(cp.window))+int64(i))&ringMask] = b
	}
	if r := uint(cp.bit % 8); r != 0 {
		if !d.need(r) {
			return nil, io.ErrUnexpectedEOF
		}
		d.drop(r)
	}
	return d, nil
}

// checkpointAt records a block boundary passed by a decoder, at least an
// interval from its neighbours. A window of zeros is not stored: a decoder
// restarting there begins with a zeroed history anyway.
func (s *Seekable) checkpointAt(d *decoder) {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	i := len(s.points)
	for i > 0 && s.points[i-1].out > d.out {
		i--
	}
	if i > 0 && d.out < s.points[i-1].out+s.interval || i < len(s.points) && s.points[i].out < d.out+s.interval {
		return
	}
	n := min(d.out, windowSize)
	var w []byte
	for k := int64(0); k < n; k++ {
		if d.ring[(d.out-n+k)&ringMask] != 0 {
			w = make([]byte, n)
			for j := int64(0); j < n; j++ {
				w[j] = d.ring[(d.out-n+j)&ringMask]
			}
			break
		}
	}
	cp := checkpoint{bit: d.inPos*8 - int64(d.nbits), out: d.out, window: w}
	s.points = append(s.points, checkpoint{})
	copy(s.points[i+1:], s.points[i:])
	s.points[i] = cp
}

// ---- decoder ----

type huffman struct {
	fast    [1 << fastBits]uint16 // symbol<<4 | length; 0 when the code is longer
	count   [16]uint16
	symbols [320]uint16
}

func (h *huffman) build(lengths []uint8) error {
	h.count = [16]uint16{}
	for _, l := range lengths {
		h.count[l]++
	}
	h.count[0] = 0
	left := 1
	for l := 1; l < 16; l++ {
		left = left*2 - int(h.count[l])
		if left < 0 {
			return errors.New("deflate: oversubscribed code")
		}
	}
	var offs [17]uint16
	for l := 1; l < 16; l++ {
		offs[l+1] = offs[l] + h.count[l]
	}
	for sym, l := range lengths {
		if l != 0 {
			h.symbols[offs[l]] = uint16(sym)
			offs[l]++
		}
	}
	h.fast = [1 << fastBits]uint16{}
	var next [16]uint32
	code := uint32(0)
	for l := 1; l < 16; l++ {
		code = (code + uint32(h.count[l-1])) << 1
		next[l] = code
	}
	for sym, l := range lengths {
		if l == 0 {
			continue
		}
		c := next[l]
		next[l]++
		if int(l) > fastBits {
			continue
		}
		rev := uint32(0)
		for i := uint8(0); i < l; i++ {
			rev |= (c >> i & 1) << (l - 1 - i)
		}
		for i := rev; i < 1<<fastBits; i += 1 << l {
			h.fast[i] = uint16(sym)<<4 | uint16(l)
		}
	}
	return nil
}

// The decoder writes into a ring of decoded output that holds the 32 KiB
// window plus up to maxAhead bytes not yet handed to the reader. Input bits
// are refilled eight bytes at a time; matches are copied with copy() in
// chunks that never overlap.
const (
	ringSize = 1 << 17
	ringMask = ringSize - 1
	maxAhead = 64 << 10
)

type decoder struct {
	src   io.ReaderAt
	csize int64
	seek  *Seekable

	inPos int64 // next input byte to fetch into bits
	buf   [64 << 10]byte
	bufAt int64 // input offset of buf[0]
	bufN  int
	bits  uint64
	nbits uint

	ring []byte
	out  int64 // decoded bytes produced

	// block state
	inBlock  bool
	final    bool
	done     bool
	stored   int // remaining stored bytes
	lit      *huffman
	dist     *huffman
	dyn      [2]huffman
	copyLen  int
	copyDist int
	copyFrom int64 // decoded offset one period before the match began
}

var fixedLit, fixedDist huffman

func init() {
	var l [288]uint8
	for i := range l {
		switch {
		case i < 144:
			l[i] = 8
		case i < 256:
			l[i] = 9
		case i < 280:
			l[i] = 7
		default:
			l[i] = 8
		}
	}
	fixedLit.build(l[:])
	var d [30]uint8
	for i := range d {
		d[i] = 5
	}
	fixedDist.build(d[:])
}

func (d *decoder) byteAt(i int64) (byte, bool) {
	if i >= d.csize {
		return 0, false
	}
	if i < d.bufAt || i >= d.bufAt+int64(d.bufN) {
		if !d.load(i) {
			return 0, false
		}
	}
	return d.buf[i-d.bufAt], true
}

// load fills the input buffer starting at input offset i.
func (d *decoder) load(i int64) bool {
	n, err := d.src.ReadAt(d.buf[:min(int64(len(d.buf)), d.csize-i)], i)
	if n == 0 && err != nil {
		return false
	}
	d.bufAt, d.bufN = i, n
	return true
}

// need ensures at least n bits are buffered (fewer only at end of input).
func (d *decoder) need(n uint) bool {
	for d.nbits < n {
		b, ok := d.byteAt(d.inPos)
		if !ok {
			return false
		}
		d.inPos++
		d.bits |= uint64(b) << d.nbits
		d.nbits += 8
	}
	return true
}

// refill tops the bit buffer up to at least 56 bits where input remains,
// eight bytes at a time when they are buffered.
func (d *decoder) refill() {
	i := d.inPos - d.bufAt
	if i < 0 || i+8 > int64(d.bufN) {
		if d.inPos+8 <= d.csize && d.load(d.inPos) && d.bufN >= 8 {
			i = 0
		} else {
			d.fill()
			return
		}
	}
	k := (63 - d.nbits) >> 3
	v := binary.LittleEndian.Uint64(d.buf[i:])
	v &= 1<<(k*8) - 1
	d.bits |= v << d.nbits
	d.inPos += int64(k)
	d.nbits += k * 8
}

func (d *decoder) fill() {
	for d.nbits <= 56 {
		b, ok := d.byteAt(d.inPos)
		if !ok {
			return
		}
		d.inPos++
		d.bits |= uint64(b) << d.nbits
		d.nbits += 8
	}
}

func (d *decoder) drop(n uint) { d.bits >>= n; d.nbits -= n }

func (d *decoder) take(n uint) (int, error) {
	if !d.need(n) {
		return 0, io.ErrUnexpectedEOF
	}
	v := int(d.bits & (1<<n - 1))
	d.drop(n)
	return v, nil
}

func (d *decoder) sym(h *huffman) (int, error) {
	if d.nbits < 15 {
		d.refill()
	}
	if e := h.fast[d.bits&(1<<fastBits-1)]; e != 0 {
		l := uint(e & 15)
		if l > d.nbits {
			return 0, io.ErrUnexpectedEOF
		}
		d.drop(l)
		return int(e >> 4), nil
	}
	code, first, index := 0, 0, 0
	for l := 1; l < 16; l++ {
		if d.nbits == 0 {
			return 0, io.ErrUnexpectedEOF
		}
		code |= int(d.bits & 1)
		d.drop(1)
		count := int(h.count[l])
		if code-first < count {
			return int(h.symbols[index+code-first]), nil
		}
		index += count
		first = (first + count) << 1
		code <<= 1
	}
	return 0, errors.New("deflate: invalid code")
}

var lenBase = [...]uint16{3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258}
var lenExtra = [...]uint8{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0}
var distBase = [...]uint16{1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577}
var distExtra = [...]uint8{0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13}
var clOrder = [...]int{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}

func (d *decoder) header() error {
	d.seek.checkpointAt(d)
	v, err := d.take(3)
	if err != nil {
		return err
	}
	d.final = v&1 != 0
	switch v >> 1 {
	case 0:
		d.drop(d.nbits % 8)
		n, err := d.take(16)
		if err != nil {
			return err
		}
		nn, err := d.take(16)
		if err != nil {
			return err
		}
		if n != ^nn&0xffff {
			return errors.New("deflate: stored length mismatch")
		}
		d.stored = n
		d.lit = nil
	case 1:
		d.lit, d.dist = &fixedLit, &fixedDist
	case 2:
		hlit, err := d.take(5)
		if err != nil {
			return err
		}
		hdist, err := d.take(5)
		if err != nil {
			return err
		}
		hclen, err := d.take(4)
		if err != nil {
			return err
		}
		var cl [19]uint8
		for i := 0; i < hclen+4; i++ {
			v, err := d.take(3)
			if err != nil {
				return err
			}
			cl[clOrder[i]] = uint8(v)
		}
		var clh huffman
		if err := clh.build(cl[:]); err != nil {
			return err
		}
		lengths := make([]uint8, hlit+257+hdist+1)
		for i := 0; i < len(lengths); {
			s, err := d.sym(&clh)
			if err != nil {
				return err
			}
			switch {
			case s < 16:
				lengths[i] = uint8(s)
				i++
			default:
				rep, val := 0, uint8(0)
				switch s {
				case 16:
					if i == 0 {
						return errors.New("deflate: repeat with no previous length")
					}
					x, err := d.take(2)
					if err != nil {
						return err
					}
					rep, val = 3+x, lengths[i-1]
				case 17:
					x, err := d.take(3)
					if err != nil {
						return err
					}
					rep = 3 + x
				case 18:
					x, err := d.take(7)
					if err != nil {
						return err
					}
					rep = 11 + x
				}
				if i+rep > len(lengths) {
					return errors.New("deflate: code lengths overflow")
				}
				for ; rep > 0; rep-- {
					lengths[i] = val
					i++
				}
			}
		}
		if err := d.dyn[0].build(lengths[:hlit+257]); err != nil {
			return err
		}
		if err := d.dyn[1].build(lengths[hlit+257:]); err != nil {
			return err
		}
		d.lit, d.dist = &d.dyn[0], &d.dyn[1]
	default:
		return errors.New("deflate: invalid block type")
	}
	d.inBlock = true
	return nil
}

// read decodes into p.
func (d *decoder) read(p []byte) (int, error) {
	start := d.out
	err := d.decode(start + int64(min(len(p), maxAhead)))
	n := int(d.out - start)
	at := int(start & ringMask)
	if k := copy(p[:n], d.ring[at:min(at+n, ringSize)]); k < n {
		copy(p[k:n], d.ring[:n-k])
	}
	return n, err
}

// skip decodes up to decoded offset target without returning the bytes.
func (d *decoder) skip(target int64) error {
	for d.out < target {
		if err := d.decode(min(target, d.out+maxAhead)); err != nil {
			return err
		}
	}
	return nil
}

// copyMatch copies k bytes of the current match. From one period before
// the match began, the output repeats with period dist, so a chunk may copy
// from any whole number of periods back within that span: chunks of an
// overlapping match (a distance shorter than the length) grow as it
// proceeds.
func (d *decoder) copyMatch(k int) {
	dist := int64(d.copyDist)
	for k > 0 {
		// Whole periods decoded since one period before the match began.
		back := (d.out - d.copyFrom) / dist * dist
		src := d.out - back
		dst := int(d.out & ringMask)
		s := int(src & ringMask)
		chunk := min(k, int(back), ringSize-dst, ringSize-s)
		copy(d.ring[dst:dst+chunk], d.ring[s:s+chunk])
		d.out += int64(chunk)
		k -= chunk
		d.copyLen -= chunk
	}
}

// copyStored copies k bytes of a stored block.
func (d *decoder) copyStored(k int) error {
	for k > 0 && d.nbits >= 8 {
		d.ring[d.out&ringMask] = byte(d.bits)
		d.drop(8)
		d.out++
		d.stored--
		k--
	}
	for k > 0 {
		i := d.inPos - d.bufAt
		if i < 0 || i >= int64(d.bufN) {
			if d.inPos >= d.csize || !d.load(d.inPos) {
				return io.ErrUnexpectedEOF
			}
			i = 0
		}
		dst := int(d.out & ringMask)
		c := min(k, d.bufN-int(i), ringSize-dst)
		copy(d.ring[dst:dst+c], d.buf[i:int(i)+c])
		d.inPos += int64(c)
		d.out += int64(c)
		d.stored -= c
		k -= c
	}
	return nil
}

// decode produces output up to decoded offset target (which must be at most
// maxAhead beyond the current offset), stopping early only at the end of
// the stream (io.EOF) or on an error.
func (d *decoder) decode(target int64) error {
	for d.out < target {
		if d.copyLen > 0 {
			d.copyMatch(min(d.copyLen, int(target-d.out)))
			continue
		}
		if !d.inBlock {
			if d.done {
				return io.EOF
			}
			if err := d.header(); err != nil {
				return err
			}
		}
		if d.lit == nil { // stored block
			if err := d.copyStored(min(d.stored, int(target-d.out))); err != nil {
				return err
			}
			if d.stored == 0 {
				d.endBlock()
			}
			continue
		}
		if err := d.fast(target); err != nil {
			return err
		}
		if !d.inBlock || d.out >= target || d.copyLen > 0 {
			continue
		}
		if err := d.slow(); err != nil {
			return err
		}
	}
	return nil
}

// fast decodes symbols while a whole literal/length/distance sequence (at
// most 48 bits) is buffered, every code is in the fast tables and the
// longest match fits before target.
func (d *decoder) fast(target int64) error {
	lit, dist := d.lit, d.dist
	for d.out+258 <= target {
		if d.nbits < 48 {
			d.refill()
			if d.nbits < 48 {
				return nil
			}
		}
		e := lit.fast[d.bits&(1<<fastBits-1)]
		if e == 0 {
			return nil
		}
		d.drop(uint(e & 15))
		s := int(e >> 4)
		if s < 256 {
			d.ring[d.out&ringMask] = byte(s)
			d.out++
			continue
		}
		if s == 256 {
			d.endBlock()
			return nil
		}
		s -= 257
		if s >= len(lenBase) {
			return errors.New("deflate: invalid length symbol")
		}
		x := uint(lenExtra[s])
		length := int(lenBase[s]) + int(d.bits&(1<<x-1))
		d.drop(x)
		de := dist.fast[d.bits&(1<<fastBits-1)]
		var ds int
		if de != 0 {
			d.drop(uint(de & 15))
			ds = int(de >> 4)
		} else {
			var err error
			if ds, err = d.sym(dist); err != nil {
				return err
			}
		}
		if ds >= len(distBase) {
			return errors.New("deflate: invalid distance symbol")
		}
		y := uint(distExtra[ds])
		if d.nbits < y {
			d.refill()
		}
		dd := int(distBase[ds]) + int(d.bits&(1<<y-1))
		d.drop(y)
		if int64(dd) > d.out {
			return errors.New("deflate: distance before start")
		}
		d.copyLen, d.copyDist, d.copyFrom = length, dd, d.out-int64(dd)
		d.copyMatch(length)
	}
	return nil
}

// slow decodes one symbol with full input checks.
func (d *decoder) slow() error {
	s, err := d.sym(d.lit)
	if err != nil {
		return err
	}
	switch {
	case s < 256:
		d.ring[d.out&ringMask] = byte(s)
		d.out++
	case s == 256:
		d.endBlock()
	default:
		s -= 257
		if s >= len(lenBase) {
			return errors.New("deflate: invalid length symbol")
		}
		x, err := d.take(uint(lenExtra[s]))
		if err != nil {
			return err
		}
		length := int(lenBase[s]) + x
		ds, err := d.sym(d.dist)
		if err != nil {
			return err
		}
		if ds >= len(distBase) {
			return errors.New("deflate: invalid distance symbol")
		}
		y, err := d.take(uint(distExtra[ds]))
		if err != nil {
			return err
		}
		dist := int(distBase[ds]) + y
		if int64(dist) > d.out {
			return errors.New("deflate: distance before start")
		}
		d.copyLen, d.copyDist, d.copyFrom = length, dist, d.out-int64(dist)
	}
	return nil
}

func (d *decoder) endBlock() {
	d.inBlock = false
	if d.final {
		d.done = true
	}
}
