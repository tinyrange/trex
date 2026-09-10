package lzms

import "fmt"

var positionSlotRuns = [...]int{9, 0, 9, 7, 10, 15, 15, 20, 20, 30, 33, 40, 42, 45, 60, 73, 80, 85, 95, 105, 6}
var lengthSlotRuns = [...]int{27, 4, 6, 4, 5, 2, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1}

type slotTable struct {
	bases     []uint32
	extraBits []uint8
}

func generateSlotTable(runs []int, terminal uint32) (slotTable, error) {
	var current uint64
	bases := make([]uint32, 0)
	for order, run := range runs {
		width := uint64(1) << order
		for range run {
			current += width
			if current >= uint64(terminal) {
				return slotTable{}, fmt.Errorf("lzms: slot base %#x reaches terminal %#x", current, terminal)
			}
			bases = append(bases, uint32(current))
		}
	}
	if len(bases) < 2 {
		return slotTable{}, fmt.Errorf("lzms: slot table has %d entries", len(bases))
	}
	extra := make([]uint8, len(bases))
	for index, base := range bases {
		next := terminal
		if index+1 < len(bases) {
			next = bases[index+1]
		}
		width := next - base
		if width == 0 {
			return slotTable{}, fmt.Errorf("lzms: empty slot %d", index)
		}
		extra[index] = uint8(31 - leadingZeros32(width))
	}
	return slotTable{bases: bases, extraBits: extra}, nil
}

func leadingZeros32(value uint32) int {
	if value == 0 {
		return 32
	}
	zeros := 0
	for value&0x80000000 == 0 {
		zeros++
		value <<= 1
	}
	return zeros
}

func (t slotTable) decode(symbol int, reader *backwardBitReader) (uint32, error) {
	if symbol < 0 || symbol >= len(t.bases) {
		return 0, fmt.Errorf("lzms: slot symbol %d outside alphabet of %d", symbol, len(t.bases))
	}
	extra, err := reader.readBits(uint(t.extraBits[symbol]))
	if err != nil {
		return 0, err
	}
	value := uint64(t.bases[symbol]) + uint64(extra)
	if value > 0x7ffffffe {
		return 0, fmt.Errorf("lzms: slot %d value %#x exceeds signed block limit", symbol, value)
	}
	return uint32(value), nil
}

func (t slotTable) symbolsForOutputSize(size int) (int, error) {
	if size <= 1 {
		// No offset can be referenced before at least one byte is output, but
		// Huffman construction still requires a binary alphabet.
		return min(2, len(t.bases)), nil
	}
	value := uint32(size - 1)
	for index := range t.bases {
		next := uint32(0x7fffffff)
		if index+1 < len(t.bases) {
			next = t.bases[index+1]
		}
		if t.bases[index] <= value && value < next {
			return index + 1, nil
		}
	}
	return 0, fmt.Errorf("lzms: output size %d has no position slot", size)
}
