package lzx

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	lzxMinMatch            = 2
	lzxNumChars            = 256
	lzxBlockVerbatim       = 1
	lzxBlockAligned        = 2
	lzxBlockUncompressed   = 3
	lzxNumPrimaryLengths   = 7
	lzxNumSecondaryLengths = 249
	lzxPreTreeSymbols      = 20
	lzxAlignedSymbols      = 8
	lzxFrameSize           = 32768
)

type lzxDecoder struct {
	windowSize   int
	r0, r1, r2   int
	mainLens     []byte
	lengthLens   []byte
	mainTree     lzxHuffman
	lengthTree   lzxHuffman
	alignedTree  lzxHuffman
	preTree      lzxHuffman
	aligned      bool
	posBase      []int
	extraBits    []int
	intelSize    int32
	intelStarted bool
}

// Decompress decodes a Microsoft LZX stream.
func Decompress(data []byte, windowBits int, outSize int) ([]byte, error) {
	if outSize < 0 {
		return nil, fmt.Errorf("lzx: negative output size")
	}
	dec, err := newLZXDecoder(windowBits)
	if err != nil {
		return nil, err
	}
	br := newLZXBitReader(data)
	if br.readBits(1) == 1 {
		hi := br.readBits(16)
		lo := br.readBits(16)
		dec.intelSize = int32((hi << 16) | lo)
	}
	out := make([]byte, 0, outSize)
	for len(out) < outSize {
		if err := dec.decodeBlock(br, &out, outSize); err != nil {
			return nil, err
		}
	}
	// Keep history in its original, pre-E8 form until all matches are decoded.
	// The API already retains the whole output, so a second window is needless.
	for frameStart := 0; frameStart < len(out); frameStart += lzxFrameSize {
		dec.undoE8(out[frameStart:min(frameStart+lzxFrameSize, len(out))], frameStart)
	}
	return out[:outSize], nil
}

// DecompressWIMChunk decodes an LZX chunk using the WIM framing variant.
func DecompressWIMChunk(data []byte, windowBits int, outSize int) ([]byte, error) {
	if outSize < 0 {
		return nil, fmt.Errorf("lzx: negative output size")
	}
	if len(data) == outSize {
		return append([]byte(nil), data...), nil
	}
	dec, err := newLZXDecoder(windowBits)
	if err != nil {
		return nil, err
	}
	dec.intelStarted = true
	dec.intelSize = 12000000
	br := newLZXBitReader(data)
	out := make([]byte, 0, outSize)
	for len(out) < outSize {
		if err := dec.decodeWIMBlock(br, &out, outSize); err != nil {
			return nil, err
		}
	}
	dec.undoE8(out, 0)
	return out[:outSize], nil
}

func newLZXDecoder(windowBits int) (*lzxDecoder, error) {
	if windowBits < 15 || windowBits > 21 {
		return nil, fmt.Errorf("lzx: unsupported window size %d", windowBits)
	}
	posSlots := lzxPositionSlots(windowBits)
	extraBits := make([]int, posSlots)
	posBase := make([]int, posSlots)
	base := 0
	for slot := 0; slot < posSlots; slot++ {
		posBase[slot] = base
		extraBits[slot] = lzxSlotExtraBits(slot)
		base += 1 << uint(extraBits[slot])
	}
	return &lzxDecoder{
		windowSize: 1 << uint(windowBits),
		r0:         1,
		r1:         1,
		r2:         1,
		mainLens:   make([]byte, lzxNumChars+posSlots*8),
		lengthLens: make([]byte, lzxNumSecondaryLengths),
		posBase:    posBase,
		extraBits:  extraBits,
	}, nil
}

func lzxPositionSlots(windowBits int) int {
	switch windowBits {
	case 20:
		return 42
	case 21:
		return 50
	default:
		return windowBits * 2
	}
}

func lzxSlotExtraBits(slot int) int {
	if slot < 4 {
		return 0
	}
	if slot >= 36 {
		return 17
	}
	return slot/2 - 1
}

func (d *lzxDecoder) decodeBlock(br *lzxBitReader, out *[]byte, outSize int) error {
	blockType := int(br.readBits(3))
	declaredBlockLen := int(br.readBits(16)<<8 | br.readBits(8))
	blockLen := declaredBlockLen
	if blockLen > outSize-len(*out) {
		blockLen = outSize - len(*out)
	}
	switch blockType {
	case lzxBlockVerbatim, lzxBlockAligned:
		if blockType == lzxBlockAligned {
			lens := make([]byte, lzxAlignedSymbols)
			for i := range lens {
				lens[i] = byte(br.readBits(3))
			}
			d.aligned = true
			if err := d.alignedTree.reset(lens); err != nil {
				return err
			}
		} else {
			d.aligned = false
		}
		if err := d.readLengths(br, d.mainLens, 0, lzxNumChars); err != nil {
			return fmt.Errorf("main literal lengths: %w", err)
		}
		if err := d.readLengths(br, d.mainLens, lzxNumChars, len(d.mainLens)); err != nil {
			return fmt.Errorf("main match lengths: %w", err)
		}
		if err := d.mainTree.reset(d.mainLens); err != nil {
			return err
		}
		if d.mainLens[0xe8] != 0 {
			d.intelStarted = true
		}
		if err := d.readLengths(br, d.lengthLens, 0, len(d.lengthLens)); err != nil {
			return fmt.Errorf("secondary lengths: %w", err)
		}
		if err := d.lengthTree.reset(d.lengthLens); err != nil {
			return err
		}
		if err := d.decodeCompressedBlock(br, out, len(*out)+blockLen); err != nil {
			return err
		}
	case lzxBlockUncompressed:
		br.align16Always()
		if br.remaining() < 12 {
			return fmt.Errorf("lzx: truncated uncompressed block")
		}
		d.r0 = int(binary.LittleEndian.Uint32(br.takeBytes(4)))
		d.r1 = int(binary.LittleEndian.Uint32(br.takeBytes(4)))
		d.r2 = int(binary.LittleEndian.Uint32(br.takeBytes(4)))
		d.intelStarted = true
		data := br.takeBytes(blockLen)
		if br.err != nil {
			return br.err
		}
		d.putBytes(out, data)
		if declaredBlockLen&1 != 0 && len(*out) < outSize {
			_ = br.takeBytes(1)
		}
	default:
		return fmt.Errorf("lzx: invalid block type %d at output %d byte %d bit %d", blockType, len(*out), br.bytePosition(), br.bitPosition())
	}
	if len(*out)%lzxFrameSize == 0 && len(*out) < outSize {
		br.align16()
	}
	if br.err != nil {
		return fmt.Errorf("lzx: block type %d output %d input byte %d bit %d: %w", blockType, len(*out), br.bytePosition(), br.bitPosition(), br.err)
	}
	return nil
}

func (d *lzxDecoder) decodeWIMBlock(br *lzxBitReader, out *[]byte, outSize int) error {
	blockType := int(br.readBits(3))
	defaultSize := br.readBits(1)
	blockLen := lzxFrameSize
	if defaultSize == 0 {
		if d.windowSize == lzxFrameSize {
			blockLen = int(br.readBits(16))
		} else {
			blockLen = int(br.readBits(16)<<8 | br.readBits(8))
		}
	}
	if blockLen > outSize-len(*out) {
		blockLen = outSize - len(*out)
	}
	switch blockType {
	case lzxBlockVerbatim, lzxBlockAligned:
		if blockType == lzxBlockAligned {
			lens := make([]byte, lzxAlignedSymbols)
			for i := range lens {
				lens[i] = byte(br.readBits(3))
			}
			d.aligned = true
			if err := d.alignedTree.reset(lens); err != nil {
				return err
			}
		} else {
			d.aligned = false
		}
		if err := d.readLengths(br, d.mainLens, 0, lzxNumChars); err != nil {
			return fmt.Errorf("main literal lengths: %w", err)
		}
		if err := d.readLengths(br, d.mainLens, lzxNumChars, len(d.mainLens)); err != nil {
			return fmt.Errorf("main match lengths: %w", err)
		}
		if err := d.mainTree.reset(d.mainLens); err != nil {
			return err
		}
		if d.mainLens[0xe8] != 0 {
			d.intelStarted = true
		}
		if err := d.readLengths(br, d.lengthLens, 0, len(d.lengthLens)); err != nil {
			return fmt.Errorf("secondary lengths: %w", err)
		}
		if err := d.lengthTree.reset(d.lengthLens); err != nil {
			return err
		}
		if err := d.decodeCompressedBlock(br, out, len(*out)+blockLen); err != nil {
			return err
		}
	case lzxBlockUncompressed:
		br.align16Always()
		if br.remaining() < 12 {
			return fmt.Errorf("lzx: truncated uncompressed block")
		}
		d.r0 = int(binary.LittleEndian.Uint32(br.takeBytes(4)))
		d.r1 = int(binary.LittleEndian.Uint32(br.takeBytes(4)))
		d.r2 = int(binary.LittleEndian.Uint32(br.takeBytes(4)))
		d.intelStarted = true
		data := br.takeBytes(blockLen)
		if br.err != nil {
			return br.err
		}
		d.putBytes(out, data)
		if blockLen&1 != 0 && len(*out) < outSize {
			_ = br.takeBytes(1)
		}
	default:
		return fmt.Errorf("lzx: invalid WIM block type %d at output %d byte %d bit %d", blockType, len(*out), br.bytePosition(), br.bitPosition())
	}
	if br.err != nil {
		return fmt.Errorf("lzx: WIM block type %d output %d input byte %d bit %d: %w", blockType, len(*out), br.bytePosition(), br.bitPosition(), br.err)
	}
	return nil
}

func (d *lzxDecoder) readLengths(br *lzxBitReader, lens []byte, first, last int) error {
	preLens := make([]byte, lzxPreTreeSymbols)
	for i := range preLens {
		preLens[i] = byte(br.readBits(4))
	}
	if err := d.preTree.reset(preLens); err != nil {
		return err
	}
	preTree := &d.preTree
	for i := first; i < last; {
		sym, err := preTree.decode(br)
		if err != nil {
			return err
		}
		switch sym {
		case 17:
			repeat := int(br.readBits(4)) + 4
			for ; repeat > 0 && i < last; repeat-- {
				lens[i] = 0
				i++
			}
		case 18:
			repeat := int(br.readBits(5)) + 20
			for ; repeat > 0 && i < last; repeat-- {
				lens[i] = 0
				i++
			}
		case 19:
			repeat := int(br.readBits(1)) + 4
			next, err := preTree.decode(br)
			if err != nil {
				return err
			}
			value := byte((int(lens[i]) - next + 17) % 17)
			for ; repeat > 0 && i < last; repeat-- {
				lens[i] = value
				i++
			}
		default:
			lens[i] = byte((int(lens[i]) - sym + 17) % 17)
			i++
		}
	}
	return br.err
}

func (d *lzxDecoder) decodeCompressedBlock(br *lzxBitReader, out *[]byte, end int) error {
	for len(*out) < end {
		sym, err := d.mainTree.decode(br)
		if err != nil {
			return fmt.Errorf("main symbol at output %d: %w", len(*out), err)
		}
		if sym < lzxNumChars {
			d.putByte(out, byte(sym))
			if len(*out)%lzxFrameSize == 0 && len(*out) < end {
				br.align16()
			}
			continue
		}
		match := sym - lzxNumChars
		length := (match & 7) + lzxMinMatch
		if match&7 == lzxNumPrimaryLengths {
			if d.lengthTree.empty {
				return fmt.Errorf("lzx: empty length tree used at output %d", len(*out))
			}
			extra, err := d.lengthTree.decode(br)
			if err != nil {
				return fmt.Errorf("length symbol at output %d: %w", len(*out), err)
			}
			length += extra
		}
		slot := match >> 3
		offset, err := d.matchOffset(br, slot)
		if err != nil {
			return err
		}
		if offset <= 0 || offset > d.windowSize {
			return fmt.Errorf("lzx: invalid match offset %d", offset)
		}
		start := len(*out)
		d.putMatch(out, offset, min(length, end-start))
		// Matches contain no intervening input bits, so one alignment suffices
		// even if the copy crosses a frame boundary. Do not align at block end.
		if start/lzxFrameSize != len(*out)/lzxFrameSize && (len(*out)%lzxFrameSize != 0 || len(*out) < end) {
			br.align16()
		}
	}
	return br.err
}

func (d *lzxDecoder) matchOffset(br *lzxBitReader, slot int) (int, error) {
	switch slot {
	case 0:
		return d.r0, nil
	case 1:
		offset := d.r1
		d.r1 = d.r0
		d.r0 = offset
		return offset, nil
	case 2:
		offset := d.r2
		d.r2 = d.r0
		d.r0 = offset
		return offset, nil
	default:
		if slot >= len(d.posBase) {
			return 0, fmt.Errorf("lzx: invalid position slot %d", slot)
		}
		extra := d.extraBits[slot]
		footer := 0
		if d.aligned && extra >= 3 {
			footer = int(br.readBits(uint(extra-3)) << 3)
			aligned, err := d.alignedTree.decode(br)
			if err != nil {
				return 0, fmt.Errorf("aligned offset at slot %d: %w", slot, err)
			}
			footer += aligned
		} else if extra > 0 {
			footer = int(br.readBits(uint(extra)))
		}
		offset := d.posBase[slot] + footer - 2
		d.r2 = d.r1
		d.r1 = d.r0
		d.r0 = offset
		return offset, br.err
	}
}

func (d *lzxDecoder) putByte(out *[]byte, b byte) {
	*out = append(*out, b)
}

func (d *lzxDecoder) putBytes(out *[]byte, data []byte) {
	*out = append(*out, data...)
}

func (d *lzxDecoder) putMatch(out *[]byte, offset, length int) {
	start := len(*out)
	*out = (*out)[:start+length]
	dst := (*out)[start:]
	src := start - offset
	// Preserve the initial zero-filled history, including a match which begins
	// before the output and then continues through already decoded bytes.
	if src < 0 {
		n := min(-src, length)
		clear(dst[:n])
		dst = dst[n:]
		src += n
		if len(dst) == 0 {
			return
		}
	}
	// Expand overlapping matches by doubling the initialized prefix, never
	// reading uninitialized output (copy itself has memmove semantics).
	for len(dst) > 0 {
		n := copy(dst, (*out)[src:len(*out)-len(dst)])
		dst = dst[n:]
	}
}

func (d *lzxDecoder) undoE8(frame []byte, absoluteStart int) {
	if d.intelSize == 0 || !d.intelStarted || len(frame) <= 10 {
		return
	}
	for i := 0; i < len(frame)-10; {
		next := bytes.IndexByte(frame[i:len(frame)-10], 0xe8)
		if next < 0 {
			return
		}
		i += next
		curpos := int32(absoluteStart + i)
		value := int32(binary.LittleEndian.Uint32(frame[i+1 : i+5]))
		if value >= -curpos && value < d.intelSize {
			if value >= 0 {
				value -= curpos
			} else {
				value += d.intelSize
			}
			binary.LittleEndian.PutUint32(frame[i+1:i+5], uint32(value))
		}
		i += 5
	}
}

type lzxBitReader struct {
	data  []byte
	pos   int
	bits  uint64 // MSB-first, assembled from little-endian 16-bit words
	nbits uint
	err   error
}

func newLZXBitReader(data []byte) *lzxBitReader {
	return &lzxBitReader{data: data}
}

func (r *lzxBitReader) readBits(n uint) uint32 {
	if r.nbits < n {
		r.fill()
	}
	if r.nbits < n {
		r.err = fmt.Errorf("lzx: truncated bitstream")
		return 0
	}
	value := uint32(r.bits >> (64 - n))
	r.dropBits(n)
	return value
}

func (r *lzxBitReader) fill() {
	for r.nbits <= 48 && r.pos+1 < len(r.data) {
		r.bits |= uint64(binary.LittleEndian.Uint16(r.data[r.pos:r.pos+2])) << (48 - r.nbits)
		r.pos += 2
		r.nbits += 16
	}
}

func (r *lzxBitReader) align16() {
	r.dropBits(r.nbits % 16)
}

func (r *lzxBitReader) align16Always() {
	if r.nbits%16 == 0 {
		r.readBits(16)
	} else {
		r.align16()
	}
}

func (r *lzxBitReader) takeBytes(n int) []byte {
	r.align16()
	// Return all whole prefetched words before entering the raw-byte portion.
	r.pos -= int(r.nbits/16) * 2
	r.bits, r.nbits = 0, 0
	if r.pos+n > len(r.data) {
		r.err = fmt.Errorf("lzx: truncated byte stream")
		return nil
	}
	out := r.data[r.pos : r.pos+n]
	r.pos += n
	return out
}

func (r *lzxBitReader) remaining() int {
	return len(r.data) - r.pos + int(r.nbits/16)*2
}

func (r *lzxBitReader) bytePosition() int { return r.pos - int((r.nbits+15)/16)*2 }
func (r *lzxBitReader) bitPosition() uint { return (16 - r.nbits%16) % 16 }

type lzxHuffman struct {
	// A short-code lookup plus canonical ranges for the uncommon long codes.
	// Entries pack the symbol above a five-bit code length; zero means missing.
	table   [1 << lzxHuffmanTableBits]uint16
	count   [17]uint16
	first   [17]uint32
	index   [17]uint16
	symbols [256 + 50*8]uint16
	empty   bool
}

const lzxHuffmanTableBits = 10

func newLZXHuffman(lengths []byte) (*lzxHuffman, error) {
	h := &lzxHuffman{}
	if err := h.reset(lengths); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *lzxHuffman) reset(lengths []byte) error {
	const maxBits = 16
	*h = lzxHuffman{}
	if len(lengths) > len(h.symbols) {
		return fmt.Errorf("lzx: too many huffman symbols")
	}
	nonZero := 0
	for _, l := range lengths {
		if l > maxBits {
			return fmt.Errorf("lzx: invalid huffman length")
		}
		if l > 0 {
			h.count[l]++
			nonZero++
		}
	}
	if nonZero == 0 {
		h.empty = true
		return nil
	}
	var next [maxBits + 1]uint32
	var positions [maxBits + 1]uint16
	var code uint32
	for bits := 1; bits <= maxBits; bits++ {
		code = (code + uint32(h.count[bits-1])) << 1
		if code+uint32(h.count[bits]) > 1<<bits {
			return fmt.Errorf("lzx: oversubscribed huffman tree")
		}
		h.first[bits] = code
		h.index[bits] = h.index[bits-1] + h.count[bits-1]
		positions[bits] = h.index[bits]
		next[bits] = code
	}
	for sym, l := range lengths {
		if l == 0 {
			continue
		}
		c := next[l]
		next[l]++
		h.symbols[positions[l]] = uint16(sym)
		positions[l]++
		if l <= lzxHuffmanTableBits {
			start := int(c) << (lzxHuffmanTableBits - l)
			end := start + 1<<(lzxHuffmanTableBits-l)
			entry := uint16(sym<<5) | uint16(l)
			for i := start; i < end; i++ {
				h.table[i] = entry
			}
		}
	}
	return nil
}

func (h *lzxHuffman) decode(br *lzxBitReader) (int, error) {
	if h.empty {
		return 0, fmt.Errorf("lzx: empty huffman tree")
	}
	// At EOF the reservoir is zero-padded, but a code is accepted only when
	// all of its bits are present. Raw reads return unused prefetched words.
	if br.nbits < 16 {
		br.fill()
	}
	entry := h.table[br.bits>>(64-lzxHuffmanTableBits)]
	if n := uint(entry & 31); n != 0 && n <= br.nbits {
		br.dropBits(n)
		return int(entry >> 5), nil
	}
	peek := uint32(br.bits >> 48)
	available := min(br.nbits, 16)
	for bits := uint(lzxHuffmanTableBits + 1); bits <= available; bits++ {
		code := peek >> (16 - bits)
		if offset := code - h.first[bits]; offset < uint32(h.count[bits]) {
			br.dropBits(bits)
			return int(h.symbols[uint32(h.index[bits])+offset]), nil
		}
	}
	if available < 16 {
		br.err = fmt.Errorf("lzx: truncated bitstream")
		return 0, br.err
	}
	return 0, fmt.Errorf("lzx: invalid huffman code")
}

// dropBits consumes only a code whose presence was established by the peek.
func (br *lzxBitReader) dropBits(n uint) {
	br.bits <<= n
	br.nbits -= n
}
