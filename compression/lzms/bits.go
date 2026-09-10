// Package lzms implements raw LZMS block decompression.
package lzms

import (
	"encoding/binary"
	"fmt"
)

// backwardBitReader reads little-endian 16-bit words from the end of a raw
// block toward its beginning, exposing each word most-significant bit first.
type backwardBitReader struct {
	data     []byte
	word     int
	bitsLeft uint
	current  uint16
}

func newBackwardBitReader(data []byte) (*backwardBitReader, error) {
	if len(data)&1 != 0 {
		return nil, fmt.Errorf("lzms: odd compressed size %d", len(data))
	}
	return &backwardBitReader{data: data, word: len(data)/2 - 1}, nil
}

func (r *backwardBitReader) readBits(count uint) (uint32, error) {
	if count > 32 {
		return 0, fmt.Errorf("lzms: backward read of %d bits exceeds 32", count)
	}
	if count == 0 {
		return 0, nil
	}
	if r.bitsLeft == 0 {
		if err := r.loadWord(); err != nil {
			return 0, err
		}
	}
	if count <= r.bitsLeft {
		shift := r.bitsLeft - count
		value := uint32(r.current>>shift) & uint32((uint64(1)<<count)-1)
		r.bitsLeft -= count
		return value, nil
	}
	return r.readBitsSlow(count)
}

func (r *backwardBitReader) readBitsSlow(count uint) (uint32, error) {
	var value uint32
	for count > 0 {
		if r.bitsLeft == 0 {
			if err := r.loadWord(); err != nil {
				return 0, err
			}
		}
		take := min(count, r.bitsLeft)
		shift := r.bitsLeft - take
		mask := uint32((uint64(1) << take) - 1)
		value = value<<take | (uint32(r.current>>shift) & mask)
		r.bitsLeft -= take
		count -= take
	}
	return value, nil
}

func (r *backwardBitReader) loadWord() error {
	if r.word < 0 {
		return fmt.Errorf("lzms: truncated backward bitstream")
	}
	offset := r.word * 2
	r.current = binary.LittleEndian.Uint16(r.data[offset : offset+2])
	r.word--
	r.bitsLeft = 16
	return nil
}

func (r *backwardBitReader) peekBits(count uint) (uint32, bool) {
	if count == 0 || count > 16 {
		return 0, count == 0
	}
	if r.bitsLeft == 0 {
		if r.word < 0 {
			return 0, false
		}
		offset := r.word * 2
		r.current = binary.LittleEndian.Uint16(r.data[offset : offset+2])
		r.word--
		r.bitsLeft = 16
	}
	if count <= r.bitsLeft {
		shift := r.bitsLeft - count
		return uint32(r.current>>shift) & uint32((uint64(1)<<count)-1), true
	}
	remaining := count - r.bitsLeft
	if r.word < 0 {
		return 0, false
	}
	offset := r.word * 2
	next := binary.LittleEndian.Uint16(r.data[offset : offset+2])
	lowMask := uint32((uint64(1) << r.bitsLeft) - 1)
	return (uint32(r.current)&lowMask)<<remaining | uint32(next>>(16-remaining)), true
}

func (r *backwardBitReader) dropBits(count uint) {
	if count <= r.bitsLeft {
		r.bitsLeft -= count
		return
	}
	count -= r.bitsLeft
	offset := r.word * 2
	r.current = binary.LittleEndian.Uint16(r.data[offset : offset+2])
	r.word--
	r.bitsLeft = 16 - count
}
