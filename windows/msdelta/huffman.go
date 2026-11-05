package msdelta

import (
	"errors"
	"fmt"
)

const huffmanLookupBits = 10

type huffman struct {
	lookup  [1 << huffmanLookupBits]uint32
	first   []uint32
	offset  []int
	symbols []int
}

func newHuffman(lengths []byte, maximum int) (*huffman, error) {
	if maximum < 1 || maximum > 31 {
		return nil, errors.New("msdelta: invalid Huffman maximum length")
	}
	counts := make([]int, maximum+1)
	for _, length := range lengths {
		if int(length) > maximum {
			return nil, fmt.Errorf("msdelta: Huffman length %d exceeds %d", length, maximum)
		}
		counts[length]++
	}
	if counts[0] == len(lengths) {
		return nil, errors.New("msdelta: empty Huffman tree")
	}
	available := 1
	for bits := 1; bits <= maximum; bits++ {
		available = available*2 - counts[bits]
		if available < 0 {
			return nil, errors.New("msdelta: oversubscribed Huffman tree")
		}
	}
	// MSDelta parameter blocks may deliberately leave unused code space. The
	// canonical table remains decodable; an actually selected missing code is
	// rejected by the bounds check in decode.

	first := make([]uint32, maximum)
	sum := 0
	for bits := maximum; bits > 0; bits-- {
		first[bits-1] = uint32(sum)
		sum = (sum + counts[bits]) >> 1
	}
	offsets := make([]int, maximum)
	positions := make([]int, maximum)
	offset := counts[0]
	for bits := 0; bits < maximum; bits++ {
		offset += counts[bits+1]
		positions[bits] = len(lengths) - offset
		offsets[bits] = positions[bits] - int(first[bits])
	}
	symbols := make([]int, len(lengths)-counts[0])
	for symbol, length := range lengths {
		if length == 0 {
			continue
		}
		position := positions[int(length)-1]
		if position < 0 || position >= len(symbols) {
			return nil, errors.New("msdelta: invalid Huffman symbol position")
		}
		symbols[position] = symbol
		positions[int(length)-1]++
	}
	h := &huffman{first: first, offset: offsets, symbols: symbols}
	// Simulate the canonical decoder for each low-bit prefix. Leave long or
	// invalid codes empty so they retain the checked slow-path semantics.
	for prefix := range h.lookup {
		var code uint32
		for length := 0; length < min(maximum, huffmanLookupBits); length++ {
			code |= uint32(prefix>>length) & 1
			if code >= first[length] {
				index := int(code) + offsets[length]
				if index >= 0 && index < len(symbols) && uint64(symbols[index]) <= uint64(^uint32(0)>>5) {
					h.lookup[prefix] = uint32(symbols[index])<<5 | uint32(length+1)
				}
				break
			}
			code <<= 1
		}
	}
	return h, nil
}

func (h *huffman) decode(bits *bitReader) (int, error) {
	if bits.bitCount < huffmanLookupBits {
		bits.fill()
	}
	entry := h.lookup[bits.value&((1<<huffmanLookupBits)-1)]
	length := uint(entry & 31)
	// A short final code is valid without a full lookup-width reservoir.
	// Never consume padding or accept a truncated longer code.
	if length != 0 && length <= bits.bitCount {
		bits.value >>= length
		bits.bitCount -= length
		return int(entry >> 5), nil
	}
	return h.decodeSlow(bits)
}

func (h *huffman) decodeSlow(bits *bitReader) (int, error) {
	var code uint32
	for length := 0; length < len(h.first); length++ {
		bit, err := bits.read(1)
		if err != nil {
			return 0, err
		}
		code |= uint32(bit)
		if code >= h.first[length] {
			index := int(code) + h.offset[length]
			if index < 0 || index >= len(h.symbols) {
				return 0, errors.New("msdelta: invalid Huffman code")
			}
			return h.symbols[index], nil
		}
		code <<= 1
	}
	return 0, errors.New("msdelta: Huffman code exceeds maximum length")
}

func defaultHuffmanLengths(size int) []byte {
	length := 1
	for 1<<length < size {
		length++
	}
	shorter := (1 << length) - size
	result := make([]byte, size)
	for index := range result {
		result[index] = byte(length)
		if index < shorter {
			result[index]--
		}
	}
	return result
}
