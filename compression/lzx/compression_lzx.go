package lzx

import (
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
	window       []byte
	windowPos    int
	r0, r1, r2   int
	mainLens     []byte
	lengthLens   []byte
	mainTree     *lzxHuffman
	lengthTree   *lzxHuffman
	alignedTree  *lzxHuffman
	posBase      []int
	extraBits    []int
	intelSize    int32
	intelStarted bool
}

// Decompress decodes a Microsoft LZX stream.
func Decompress(data []byte, windowBits int, outSize int) ([]byte, error) {
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
	frameStart := 0
	for len(out) < outSize {
		if err := dec.decodeBlock(br, &out, outSize); err != nil {
			return nil, err
		}
		for frameStart+lzxFrameSize <= len(out) {
			dec.undoE8(out[frameStart:frameStart+lzxFrameSize], frameStart)
			frameStart += lzxFrameSize
		}
	}
	if frameStart < len(out) {
		dec.undoE8(out[frameStart:], frameStart)
	}
	return out[:outSize], nil
}

// DecompressWIMChunk decodes an LZX chunk using the WIM framing variant.
func DecompressWIMChunk(data []byte, windowBits int, outSize int) ([]byte, error) {
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
		window:     make([]byte, 1<<uint(windowBits)),
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
			var err error
			d.alignedTree, err = newLZXHuffman(lens)
			if err != nil {
				return err
			}
		} else {
			d.alignedTree = nil
		}
		if err := d.readLengths(br, d.mainLens, 0, lzxNumChars); err != nil {
			return fmt.Errorf("main literal lengths: %w", err)
		}
		if err := d.readLengths(br, d.mainLens, lzxNumChars, len(d.mainLens)); err != nil {
			return fmt.Errorf("main match lengths: %w", err)
		}
		var err error
		d.mainTree, err = newLZXHuffman(d.mainLens)
		if err != nil {
			return err
		}
		if d.mainLens[0xe8] != 0 {
			d.intelStarted = true
		}
		if err := d.readLengths(br, d.lengthLens, 0, len(d.lengthLens)); err != nil {
			return fmt.Errorf("secondary lengths: %w", err)
		}
		d.lengthTree, err = newLZXHuffman(d.lengthLens)
		if err != nil {
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
		for i := 0; i < blockLen; i++ {
			b := br.takeBytes(1)
			if len(b) != 1 {
				return fmt.Errorf("lzx: truncated uncompressed data")
			}
			d.putByte(out, b[0])
		}
		if declaredBlockLen&1 != 0 && len(*out) < outSize {
			_ = br.takeBytes(1)
		}
	default:
		return fmt.Errorf("lzx: invalid block type %d at output %d byte %d bit %d", blockType, len(*out), br.pos, br.bit)
	}
	if len(*out)%lzxFrameSize == 0 && len(*out) < outSize {
		br.align16()
	}
	if br.err != nil {
		return fmt.Errorf("lzx: block type %d output %d input byte %d bit %d: %w", blockType, len(*out), br.pos, br.bit, br.err)
	}
	return nil
}

func (d *lzxDecoder) decodeWIMBlock(br *lzxBitReader, out *[]byte, outSize int) error {
	blockType := int(br.readBits(3))
	defaultSize := br.readBits(1)
	blockLen := lzxFrameSize
	if defaultSize == 0 {
		if len(d.window) == lzxFrameSize {
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
			var err error
			d.alignedTree, err = newLZXHuffman(lens)
			if err != nil {
				return err
			}
		} else {
			d.alignedTree = nil
		}
		if err := d.readLengths(br, d.mainLens, 0, lzxNumChars); err != nil {
			return fmt.Errorf("main literal lengths: %w", err)
		}
		if err := d.readLengths(br, d.mainLens, lzxNumChars, len(d.mainLens)); err != nil {
			return fmt.Errorf("main match lengths: %w", err)
		}
		var err error
		d.mainTree, err = newLZXHuffman(d.mainLens)
		if err != nil {
			return err
		}
		if d.mainLens[0xe8] != 0 {
			d.intelStarted = true
		}
		if err := d.readLengths(br, d.lengthLens, 0, len(d.lengthLens)); err != nil {
			return fmt.Errorf("secondary lengths: %w", err)
		}
		d.lengthTree, err = newLZXHuffman(d.lengthLens)
		if err != nil {
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
		for i := 0; i < blockLen; i++ {
			b := br.takeBytes(1)
			if len(b) != 1 {
				return fmt.Errorf("lzx: truncated uncompressed data")
			}
			d.putByte(out, b[0])
		}
		if blockLen&1 != 0 && len(*out) < outSize {
			_ = br.takeBytes(1)
		}
	default:
		return fmt.Errorf("lzx: invalid WIM block type %d at output %d byte %d bit %d", blockType, len(*out), br.pos, br.bit)
	}
	if br.err != nil {
		return fmt.Errorf("lzx: WIM block type %d output %d input byte %d bit %d: %w", blockType, len(*out), br.pos, br.bit, br.err)
	}
	return nil
}

func (d *lzxDecoder) readLengths(br *lzxBitReader, lens []byte, first, last int) error {
	preLens := make([]byte, lzxPreTreeSymbols)
	for i := range preLens {
		preLens[i] = byte(br.readBits(4))
	}
	preTree, err := newLZXHuffman(preLens)
	if err != nil {
		return err
	}
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
		if offset <= 0 || offset > len(d.window) {
			return fmt.Errorf("lzx: invalid match offset %d", offset)
		}
		for i := 0; i < length && len(*out) < end; i++ {
			src := (d.windowPos - offset) & (len(d.window) - 1)
			d.putByte(out, d.window[src])
			if len(*out)%lzxFrameSize == 0 && len(*out) < end {
				br.align16()
			}
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
		if d.alignedTree != nil && extra >= 3 {
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
	d.window[d.windowPos] = b
	d.windowPos = (d.windowPos + 1) & (len(d.window) - 1)
}

func (d *lzxDecoder) undoE8(frame []byte, absoluteStart int) {
	if d.intelSize == 0 || !d.intelStarted || len(frame) <= 10 {
		return
	}
	for i := 0; i < len(frame)-10; i++ {
		if frame[i] != 0xe8 {
			continue
		}
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
		i += 4
	}
}

type lzxBitReader struct {
	data   []byte
	pos    int
	word   uint16
	bit    uint
	loaded bool
	err    error
}

func newLZXBitReader(data []byte) *lzxBitReader {
	return &lzxBitReader{data: data}
}

func (r *lzxBitReader) readBits(n uint) uint32 {
	var value uint32
	for i := uint(0); i < n; i++ {
		if !r.loaded || r.bit == 16 {
			if r.pos+1 >= len(r.data) {
				r.err = fmt.Errorf("lzx: truncated bitstream")
				return 0
			}
			r.word = binary.LittleEndian.Uint16(r.data[r.pos : r.pos+2])
			r.pos += 2
			r.bit = 0
			r.loaded = true
		}
		value = (value << 1) | uint32((r.word>>(15-r.bit))&1)
		r.bit++
	}
	return value
}

func (r *lzxBitReader) align16() {
	r.bit = 16
}

func (r *lzxBitReader) align16Always() {
	if r.loaded && r.bit == 16 {
		_ = r.takeBytes(2)
		return
	}
	r.align16()
}

func (r *lzxBitReader) takeBytes(n int) []byte {
	if r.loaded && r.bit < 16 {
		r.bit = 16
	}
	if r.pos+n > len(r.data) {
		r.err = fmt.Errorf("lzx: truncated byte stream")
		return nil
	}
	out := r.data[r.pos : r.pos+n]
	r.pos += n
	return out
}

func (r *lzxBitReader) remaining() int {
	return len(r.data) - r.pos
}

type lzxHuffman struct {
	root  *lzxHuffmanNode
	empty bool
}

type lzxHuffmanNode struct {
	sym    int
	hasSym bool
	child  [2]*lzxHuffmanNode
}

func newLZXHuffman(lengths []byte) (*lzxHuffman, error) {
	const maxBits = 16
	count := make([]int, maxBits+1)
	nonZero := 0
	for _, l := range lengths {
		if l > maxBits {
			return nil, fmt.Errorf("lzx: invalid huffman length")
		}
		if l > 0 {
			count[l]++
			nonZero++
		}
	}
	root := &lzxHuffmanNode{}
	if nonZero == 0 {
		return &lzxHuffman{root: root, empty: true}, nil
	}
	next := make([]int, maxBits+1)
	code := 0
	for bits := 1; bits <= maxBits; bits++ {
		code = (code + count[bits-1]) << 1
		next[bits] = code
	}
	for sym, l := range lengths {
		if l == 0 {
			continue
		}
		c := next[l]
		next[l]++
		node := root
		for bit := int(l) - 1; bit >= 0; bit-- {
			branch := (c >> uint(bit)) & 1
			if node.child[branch] == nil {
				node.child[branch] = &lzxHuffmanNode{}
			}
			node = node.child[branch]
		}
		node.sym = sym
		node.hasSym = true
	}
	return &lzxHuffman{root: root}, nil
}

func (h *lzxHuffman) decode(br *lzxBitReader) (int, error) {
	if h.empty {
		return 0, fmt.Errorf("lzx: empty huffman tree")
	}
	node := h.root
	for node != nil {
		if node.hasSym {
			return node.sym, nil
		}
		bit := br.readBits(1)
		if br.err != nil {
			return 0, br.err
		}
		node = node.child[bit]
	}
	return 0, fmt.Errorf("lzx: invalid huffman code")
}
