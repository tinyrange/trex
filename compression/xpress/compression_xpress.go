package xpress

import (
	"encoding/binary"
	"fmt"
)

const (
	xpressSymbols = 512
	xpressTable   = 1 << 15
)

// HuffmanDecompress decodes a Microsoft XPRESS Huffman stream.
func HuffmanDecompress(data []byte, outSize int) ([]byte, error) {
	out := make([]byte, 0, outSize)
	for len(out) < outSize {
		if len(data) < 256 {
			if len(out) == outSize {
				return out, nil
			}
			return nil, fmt.Errorf("xpress: truncated huffman table")
		}
		lens := xpressCodeLengths(data[:256])
		table, err := newXPRESSDecodeTable(lens)
		if err != nil {
			return nil, err
		}
		br, err := newXPRESSBitReader(data[256:])
		if err != nil {
			return nil, err
		}
		blockEnd := len(out) + 65536
		if blockEnd > outSize {
			blockEnd = outSize
		}
		for len(out) < blockEnd {
			sym := table[br.peek15()]
			if sym < 0 || sym >= len(lens) || lens[sym] == 0 {
				return nil, fmt.Errorf("xpress: invalid huffman symbol")
			}
			if err := br.consume(int(lens[sym])); err != nil {
				return nil, err
			}
			if sym < 256 {
				out = append(out, byte(sym))
				continue
			}
			match := sym - 256
			length := match & 0x0f
			offsetBits := match >> 4
			if length == 15 {
				b, err := br.readByte()
				if err != nil {
					return nil, err
				}
				length = int(b)
				if length == 255 {
					v, err := br.readUint16()
					if err != nil {
						return nil, err
					}
					length = int(v)
					if length < 15 {
						return nil, fmt.Errorf("xpress: invalid extended match length")
					}
					length -= 15
				}
				length += 15
			}
			length += 3
			offset := 1
			if offsetBits > 0 {
				value, err := br.readBits(offsetBits)
				if err != nil {
					return nil, err
				}
				offset = int(value) + (1 << uint(offsetBits))
			}
			if offset <= 0 || offset > len(out) {
				return nil, fmt.Errorf("xpress: invalid match offset %d", offset)
			}
			for i := 0; i < length && len(out) < blockEnd; i++ {
				out = append(out, out[len(out)-offset])
			}
		}
		data = br.remainingData()
	}
	return out[:outSize], nil
}

func xpressCodeLengths(data []byte) []byte {
	lens := make([]byte, xpressSymbols)
	for i, b := range data {
		lens[i*2] = b & 0x0f
		lens[i*2+1] = b >> 4
	}
	return lens
}

func newXPRESSDecodeTable(lens []byte) ([]int, error) {
	table := make([]int, xpressTable)
	for i := range table {
		table[i] = -1
	}
	pos := 0
	for bits := byte(1); bits <= 15; bits++ {
		for sym, length := range lens {
			if length != bits {
				continue
			}
			count := 1 << uint(15-bits)
			if pos+count > len(table) {
				return nil, fmt.Errorf("xpress: invalid huffman table at symbol %d length %d position %d", sym, bits, pos)
			}
			for i := 0; i < count; i++ {
				table[pos+i] = sym
			}
			pos += count
		}
	}
	if pos != len(table) {
		return nil, fmt.Errorf("xpress: incomplete huffman table filled %d of %d", pos, len(table))
	}
	return table, nil
}

type xpressBitReader struct {
	data  []byte
	pos   int
	bits  uint32
	extra int
}

func newXPRESSBitReader(data []byte) (*xpressBitReader, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("xpress: truncated bitstream")
	}
	return &xpressBitReader{
		data:  data,
		pos:   4,
		bits:  uint32(binary.LittleEndian.Uint16(data[0:2]))<<16 | uint32(binary.LittleEndian.Uint16(data[2:4])),
		extra: 16,
	}, nil
}

func (r *xpressBitReader) peek15() int {
	return int(r.bits >> 17)
}

func (r *xpressBitReader) readBits(n int) (uint32, error) {
	value := uint32(0)
	if n > 0 {
		value = r.bits >> uint(32-n)
	}
	return value, r.consume(n)
}

func (r *xpressBitReader) consume(n int) error {
	r.bits <<= uint(n)
	r.extra -= n
	if r.extra < 0 {
		if r.pos+2 > len(r.data) {
			return fmt.Errorf("xpress: truncated bitstream")
		}
		r.bits |= uint32(binary.LittleEndian.Uint16(r.data[r.pos:r.pos+2])) << uint(-r.extra)
		r.pos += 2
		r.extra += 16
	}
	return nil
}

func (r *xpressBitReader) readByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("xpress: truncated byte stream")
	}
	b := r.data[r.pos]
	r.pos++
	return b, nil
}

func (r *xpressBitReader) readUint16() (uint16, error) {
	if r.pos+2 > len(r.data) {
		return 0, fmt.Errorf("xpress: truncated byte stream")
	}
	v := binary.LittleEndian.Uint16(r.data[r.pos : r.pos+2])
	r.pos += 2
	return v, nil
}

func (r *xpressBitReader) remainingData() []byte {
	if r.pos >= len(r.data) {
		return nil
	}
	return r.data[r.pos:]
}
