package lzx

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// IndexedReader provides bounded-working-set random access to an immutable CAB
// LZX stream. Construction decodes the complete stream once and saves compressed
// history checkpoints at block boundaries. It stores neither complete input nor
// complete output. Source bytes must remain unchanged for the reader's lifetime.
// Frame hashes bind deferred reads to the initially decoded bytes. Authenticity
// and the initial source identity remain the caller's responsibility.
type IndexedReader struct {
	mu                   sync.Mutex
	source               io.ReaderAt
	compressedSize       int64
	windowBits, size     int
	checkpoints          []lzxCheckpoint
	frameHashes          [][sha256.Size]byte
	current              *lzxReadState
	frame                [lzxFrameSize]byte
	frameStart, frameLen int
	historyDecoder       *zstd.Decoder
	scratchReserve       int64
}
type lzxReadState struct {
	dec     *lzxDecoder
	br      *lzxBitReader
	history []byte
	base    int
}
type lzxCheckpoint struct {
	input                int64
	bits                 uint64
	nbits                uint
	base, output         int
	r0, r1, r2           int
	intelSize            int32
	intelStarted         bool
	mainLens, lengthLens []byte
	history              []byte
	raw                  bool
}

// NewIndexedReader eagerly validates the stream and creates restart points at
// the first block boundary at least spacing output bytes after the previous
// checkpoint. spacing must be at least one window. A format block can exceed
// spacing; seeking can therefore decode up to spacing plus one 24-bit block.
func NewIndexedReader(source io.ReaderAt, compressedSize int64, windowBits, outSize, spacing int) (*IndexedReader, error) {
	if source == nil || compressedSize < 0 || compressedSize > int64(int(^uint(0)>>1)) || outSize < 0 {
		return nil, fmt.Errorf("lzx: invalid indexed source or size")
	}
	dec, err := newLZXDecoder(windowBits)
	if err != nil {
		return nil, err
	}
	if spacing < dec.windowSize {
		return nil, fmt.Errorf("lzx: checkpoint spacing smaller than window")
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(lzxInputBufferSize), zstd.WithLowerEncoderMem(true))
	if err != nil {
		return nil, err
	}
	defer encoder.Close()
	br := &lzxBitReader{reader: source, size: compressedSize}
	if br.readBits(1) == 1 {
		hi, lo := br.readBits(16), br.readBits(16)
		dec.intelSize = int32(hi<<16 | lo)
	}
	// Match Decompress for empty output: it does not require a stream header.
	r := &IndexedReader{source: source, compressedSize: compressedSize, windowBits: windowBits, size: outSize, frameStart: -1}
	state := &lzxReadState{dec: dec, br: br}
	var encoded []byte
	save := func() {
		cp := lzxCheckpoint{input: br.base + int64(br.pos), bits: br.bits, nbits: br.nbits, base: state.base, output: state.base + len(state.history), r0: dec.r0, r1: dec.r1, r2: dec.r2, intelSize: dec.intelSize, intelStarted: dec.intelStarted, mainLens: bytes.Clone(dec.mainLens), lengthLens: bytes.Clone(dec.lengthLens)}
		encoded = encoder.EncodeAll(state.history, encoded[:0])
		if len(encoded) >= len(state.history) {
			cp.history = bytes.Clone(state.history)
			cp.raw = true
		} else {
			// EncodeAll reserves input-sized capacity even for tiny output.
			// Only the encoded bytes belong to a persistent checkpoint.
			cp.history = bytes.Clone(encoded)
		}
		r.checkpoints = append(r.checkpoints, cp)
	}
	save()
	last, verified := 0, 0
	for state.base+len(state.history) < outSize {
		state.trim()
		if err := dec.decodeBlock(br, &state.history, outSize-state.base); err != nil {
			return nil, err
		}
		// A restart can grow from a different checkpoint history length.
		// Reserve twice the observed history capacity, the largest compressed
		// input buffer (raw blocks can exceed 64 KiB), plus codec/table scratch.
		r.scratchReserve = max(r.scratchReserve, int64(2*cap(state.history)+cap(br.buffer))+(1<<20))
		end := state.base + len(state.history)
		complete := end / lzxFrameSize * lzxFrameSize
		if end == outSize {
			complete = end
		}
		for verified < complete {
			n := min(lzxFrameSize, complete-verified)
			r.frameHashes = append(r.frameHashes, sha256.Sum256(state.history[verified-state.base:verified-state.base+n]))
			verified += n
		}
		if end-last >= spacing && end < outSize {
			state.trim()
			save()
			last = end
		}
	}
	return r, nil
}
func (s *lzxReadState) trim() {
	// Preserve frame alignment and at least one complete raw match window.
	trim := (len(s.history) - s.dec.windowSize) / lzxFrameSize * lzxFrameSize
	if trim >= s.dec.windowSize {
		copy(s.history, s.history[trim:])
		s.history = s.history[:len(s.history)-trim]
		s.base += trim
	}
}
func (r *IndexedReader) restore(cp *lzxCheckpoint) error {
	// Reuse scratch across random seeks. Reallocating multi-megabyte histories
	// at each checkpoint restart turns small paging reads into GC pressure.
	state := r.current
	r.current = nil // a failed restore must not expose partially reset state
	var err error
	if state == nil {
		state = &lzxReadState{}
		state.dec, err = newLZXDecoder(r.windowBits)
		if err != nil {
			return err
		}
		state.br = &lzxBitReader{}
	}
	dec := state.dec
	dec.aligned = false
	dec.r0, dec.r1, dec.r2 = cp.r0, cp.r1, cp.r2
	dec.intelSize, dec.intelStarted = cp.intelSize, cp.intelStarted
	copy(dec.mainLens, cp.mainLens)
	copy(dec.lengthLens, cp.lengthLens)
	history := state.history[:0]
	if cap(history) < cp.output-cp.base {
		history = make([]byte, 0, cp.output-cp.base)
	}
	if cp.raw {
		history = append(history, cp.history...)
	} else {
		if r.historyDecoder == nil {
			r.historyDecoder, err = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxWindow(lzxInputBufferSize), zstd.WithDecoderMaxMemory(uint64(2*dec.windowSize+lzxFrameSize)), zstd.WithDecodeAllCapLimit(true))
			if err != nil {
				return err
			}
		}
		history, err = r.historyDecoder.DecodeAll(cp.history, history)
		if err != nil {
			return err
		}
	}
	if len(history) != cp.output-cp.base {
		return fmt.Errorf("lzx: checkpoint history length changed")
	}
	buffer := state.br.buffer
	*state.br = lzxBitReader{reader: r.source, size: r.compressedSize, base: cp.input, bits: cp.bits, nbits: cp.nbits, buffer: buffer}
	state.history, state.base = history, cp.base
	r.current = state
	return nil
}
func (r *IndexedReader) readFrame(start int) ([]byte, error) {
	if r.frameStart == start {
		return r.frame[:r.frameLen], nil
	}
	end := min(start+lzxFrameSize, r.size)
	// Restart only for a backwards seek outside the retained raw history.
	// A forward seek may skip to a later checkpoint rather than replaying all
	// intervening blocks. Partial checkpoint frames remain raw in its history.
	index := sort.Search(len(r.checkpoints), func(i int) bool { return r.checkpoints[i].output/lzxFrameSize*lzxFrameSize > start }) - 1
	cp := &r.checkpoints[max(index, 0)]
	if r.current == nil || start < r.current.base || cp.output > r.current.base+len(r.current.history) {
		if err := r.restore(cp); err != nil {
			return nil, err
		}
	}
	s := r.current
	for s.base+len(s.history) < end {
		s.trim()
		if err := s.dec.decodeBlock(s.br, &s.history, r.size-s.base); err != nil {
			r.current = nil
			return nil, err
		}
	}
	if start < s.base || end > s.base+len(s.history) {
		return nil, fmt.Errorf("lzx: requested frame outside history")
	}
	copy(r.frame[:], s.history[start-s.base:end-s.base])
	if sha256.Sum256(r.frame[:end-start]) != r.frameHashes[start/lzxFrameSize] {
		r.current = nil
		return nil, fmt.Errorf("lzx: deferred frame %d content identity changed", start/lzxFrameSize)
	}
	s.dec.undoCABFrame(r.frame[:end-start], start)
	r.frameStart, r.frameLen = start, end-start
	return r.frame[:r.frameLen], nil
}
func (r *IndexedReader) Size() int64 { return int64(r.size) }
func (r *IndexedReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("lzx: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= int64(r.size) {
		return 0, io.EOF
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for n < len(p) && off < int64(r.size) {
		start := int(off) / lzxFrameSize * lzxFrameSize
		frame, err := r.readFrame(start)
		if err != nil {
			return n, err
		}
		count := copy(p[n:], frame[int(off)-start:])
		n += count
		off += int64(count)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// ReleaseReadCache drops only disposable decoder scratch. Checkpoints and the
// source remain valid; future reads regenerate their exact original bytes.
func (r *IndexedReader) ReleaseReadCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current = nil
	r.frameStart = -1
	r.frameLen = 0
	if r.historyDecoder != nil {
		r.historyDecoder.Close()
		r.historyDecoder = nil
	}
}

// RetainedBytes reports checkpoint payload and table storage, excluding source,
// mutable read scratch, and allocator overhead.
func (r *IndexedReader) RetainedBytes() int64 {
	n := int64(len(r.frameHashes)) * sha256.Size
	for _, cp := range r.checkpoints {
		n += int64(len(cp.history) + len(cp.mainLens) + len(cp.lengthLens) + 128)
	}
	return n
}

// ReadCacheReserve reports a conservative mutable decoder working-set allowance
// based on the blocks observed during eager validation. Cache owners should
// charge this in addition to RetainedBytes, not assume a fixed 64-KiB reader.
func (r *IndexedReader) ReadCacheReserve() int64 { return r.scratchReserve }
