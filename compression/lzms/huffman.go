package lzms

import (
	"fmt"
	"slices"
)

const maxHuffmanCodeLength = 15

type huffmanCode struct {
	lengths        []uint8
	lookup         []huffmanLookup
	symbolsByCode  []uint16
	counts         [maxHuffmanCodeLength + 1]uint32
	firstCode      [maxHuffmanCodeLength + 1]uint32
	firstIndex     [maxHuffmanCodeLength + 1]int
	leafOrder      []int
	frequencyCount []int
	nodeWeight     []uint64
	parent         []int
}

const huffmanLookupBits = 10

type huffmanLookup struct {
	symbol uint16
	bits   uint8
}

func buildHuffmanCode(frequencies []uint64) (*huffmanCode, error) {
	if len(frequencies) < 2 {
		return nil, fmt.Errorf("lzms: Huffman alphabet has %d symbols", len(frequencies))
	}
	result := &huffmanCode{}
	if err := result.rebuild(frequencies); err != nil {
		return nil, err
	}
	return result, nil
}

// rebuild derives Huffman lengths with the two-queue construction. Sorted
// leaves and generated internal nodes are each monotonic by weight, so this is
// equivalent to the specified priority queue while avoiding per-node heap
// allocation and generic container/heap comparisons.
func (h *huffmanCode) rebuild(frequencies []uint64) error {
	if len(frequencies) < 2 {
		return fmt.Errorf("lzms: Huffman alphabet has %d symbols", len(frequencies))
	}
	symbols := len(frequencies)
	nodeCount := symbols*2 - 1
	if len(h.lengths) != symbols {
		h.lengths = make([]uint8, symbols)
	}
	if len(h.leafOrder) != symbols {
		h.leafOrder = make([]int, symbols)
	}
	if len(h.nodeWeight) != nodeCount {
		h.nodeWeight = make([]uint64, nodeCount)
		h.parent = make([]int, nodeCount)
	}
	for symbol, frequency := range frequencies {
		if frequency == 0 {
			return fmt.Errorf("lzms: zero Huffman frequency for symbol %d", symbol)
		}
		h.leafOrder[symbol] = symbol
		h.nodeWeight[symbol] = frequency
		h.parent[symbol] = -1
	}
	h.sortLeaves(frequencies)
	leafPosition := 0
	internalPosition := symbols
	internalEnd := symbols
	for internalEnd < nodeCount {
		left, nextLeaf, nextInternal := takeHuffmanNode(
			frequencies, h.leafOrder, h.nodeWeight,
			leafPosition, internalPosition, internalEnd,
		)
		leafPosition, internalPosition = nextLeaf, nextInternal
		right, nextLeaf, nextInternal := takeHuffmanNode(
			frequencies, h.leafOrder, h.nodeWeight,
			leafPosition, internalPosition, internalEnd,
		)
		leafPosition, internalPosition = nextLeaf, nextInternal
		h.nodeWeight[internalEnd] = h.nodeWeight[left] + h.nodeWeight[right]
		h.parent[left] = internalEnd
		h.parent[right] = internalEnd
		h.parent[internalEnd] = -1
		internalEnd++
	}
	for symbol := range symbols {
		depth := 0
		for node := symbol; h.parent[node] >= 0; node = h.parent[node] {
			depth++
		}
		if depth == 0 || depth > maxHuffmanCodeLength {
			return fmt.Errorf("lzms: Huffman code length %d for symbol %d", depth, symbol)
		}
		h.lengths[symbol] = uint8(depth)
	}
	return canonicalHuffmanCodeInto(h.lengths, h)
}

func (h *huffmanCode) sortLeaves(frequencies []uint64) {
	if len(frequencies) <= 32 {
		for position := 1; position < len(h.leafOrder); position++ {
			symbol := h.leafOrder[position]
			index := position
			for index > 0 {
				previous := h.leafOrder[index-1]
				if frequencies[previous] < frequencies[symbol] || frequencies[previous] == frequencies[symbol] && previous < symbol {
					break
				}
				h.leafOrder[index] = previous
				index--
			}
			h.leafOrder[index] = symbol
		}
		return
	}
	var maximum uint64
	for _, frequency := range frequencies {
		if frequency > maximum {
			maximum = frequency
		}
	}
	// Adaptive LZMS frequencies are diluted every 512 or 1024 symbols and
	// stay in this compact range. Keep a general fallback for callers which
	// construct codes from arbitrary frequency sets.
	if maximum > 4096 {
		slices.SortFunc(h.leafOrder, func(a, b int) int {
			if frequencies[a] < frequencies[b] {
				return -1
			}
			if frequencies[a] > frequencies[b] {
				return 1
			}
			return a - b
		})
		return
	}
	needed := int(maximum) + 1
	if cap(h.frequencyCount) < needed {
		h.frequencyCount = make([]int, needed)
	} else {
		h.frequencyCount = h.frequencyCount[:needed]
		clear(h.frequencyCount)
	}
	for _, frequency := range frequencies {
		h.frequencyCount[frequency]++
	}
	position := 0
	for frequency, count := range h.frequencyCount {
		h.frequencyCount[frequency] = position
		position += count
	}
	for symbol, frequency := range frequencies {
		position := h.frequencyCount[frequency]
		h.leafOrder[position] = symbol
		h.frequencyCount[frequency]++
	}
}

func takeHuffmanNode(frequencies []uint64, leafOrder []int, nodeWeight []uint64, leafPosition, internalPosition, internalEnd int) (int, int, int) {
	if leafPosition < len(leafOrder) {
		leaf := leafOrder[leafPosition]
		if internalPosition >= internalEnd || frequencies[leaf] <= nodeWeight[internalPosition] {
			return leaf, leafPosition + 1, internalPosition
		}
	}
	return internalPosition, leafPosition, internalPosition + 1
}

func canonicalHuffmanCode(lengths []uint8) (*huffmanCode, error) {
	result := &huffmanCode{}
	if err := canonicalHuffmanCodeInto(lengths, result); err != nil {
		return nil, err
	}
	return result, nil
}

func canonicalHuffmanCodeInto(lengths []uint8, result *huffmanCode) error {
	counts := [maxHuffmanCodeLength + 1]uint32{}
	for symbol, length := range lengths {
		if length == 0 || length > maxHuffmanCodeLength {
			return fmt.Errorf("lzms: invalid Huffman length %d for symbol %d", length, symbol)
		}
		counts[length]++
	}
	next := [maxHuffmanCodeLength + 1]uint32{}
	var code uint32
	for bits := 1; bits <= maxHuffmanCodeLength; bits++ {
		code = (code + counts[bits-1]) << 1
		next[bits] = code
		if code+counts[bits] > 1<<bits {
			return fmt.Errorf("lzms: oversubscribed Huffman code at length %d", bits)
		}
	}
	if code+counts[maxHuffmanCodeLength] != 1<<maxHuffmanCodeLength {
		return fmt.Errorf("lzms: incomplete Huffman code")
	}
	if len(result.lengths) != len(lengths) {
		result.lengths = make([]uint8, len(lengths))
	}
	copy(result.lengths, lengths)
	if len(result.lookup) != 1<<huffmanLookupBits {
		result.lookup = make([]huffmanLookup, 1<<huffmanLookupBits)
	} else {
		clear(result.lookup)
	}
	if len(result.symbolsByCode) != len(lengths) {
		result.symbolsByCode = make([]uint16, len(lengths))
	}
	result.counts = counts
	position := 0
	for length := 1; length <= maxHuffmanCodeLength; length++ {
		result.firstCode[length] = next[length]
		result.firstIndex[length] = position
		position += int(counts[length])
	}
	positions := result.firstIndex
	for symbol, length := range lengths {
		index := positions[length]
		result.symbolsByCode[index] = uint16(symbol)
		positions[length]++
	}
	for symbol, length := range lengths {
		value := next[length]
		next[length]++
		if int(length) <= huffmanLookupBits {
			first := int(value) << uint(huffmanLookupBits-int(length))
			last := first + 1<<uint(huffmanLookupBits-int(length))
			for index := first; index < last; index++ {
				result.lookup[index] = huffmanLookup{symbol: uint16(symbol), bits: length}
			}
		}
	}
	return nil
}

func (h *huffmanCode) decode(reader *backwardBitReader) (int, error) {
	prefix, ok := reader.peekBits(huffmanLookupBits)
	if ok {
		entry := h.lookup[prefix]
		if entry.bits != 0 {
			reader.dropBits(uint(entry.bits))
			return int(entry.symbol), nil
		}
		reader.dropBits(huffmanLookupBits)
		code := prefix
		for length := huffmanLookupBits + 1; length <= maxHuffmanCodeLength; length++ {
			bit, err := reader.readBits(1)
			if err != nil {
				return 0, err
			}
			code = code<<1 | bit
			if code >= h.firstCode[length] {
				offset := code - h.firstCode[length]
				if offset < h.counts[length] {
					return int(h.symbolsByCode[h.firstIndex[length]+int(offset)]), nil
				}
			}
		}
		return 0, fmt.Errorf("lzms: invalid Huffman codeword")
	}
	var code uint32
	for length := 1; length <= maxHuffmanCodeLength; length++ {
		bit, err := reader.readBits(1)
		if err != nil {
			return 0, err
		}
		code = code<<1 | bit
		if code >= h.firstCode[length] {
			offset := code - h.firstCode[length]
			if offset < h.counts[length] {
				return int(h.symbolsByCode[h.firstIndex[length]+int(offset)]), nil
			}
		}
	}
	return 0, fmt.Errorf("lzms: Huffman codeword exceeds %d bits", maxHuffmanCodeLength)
}

type adaptiveHuffman struct {
	frequencies  []uint64
	rebuildEvery int
	decoded      int
	code         *huffmanCode
}

func newAdaptiveHuffman(symbols, rebuildEvery int) (*adaptiveHuffman, error) {
	if symbols < 2 || rebuildEvery <= 0 {
		return nil, fmt.Errorf("lzms: invalid adaptive Huffman parameters %d/%d", symbols, rebuildEvery)
	}
	frequencies := make([]uint64, symbols)
	for index := range frequencies {
		frequencies[index] = 1
	}
	code, err := buildHuffmanCode(frequencies)
	if err != nil {
		return nil, err
	}
	return &adaptiveHuffman{frequencies: frequencies, rebuildEvery: rebuildEvery, code: code}, nil
}

func (h *adaptiveHuffman) decode(reader *backwardBitReader) (int, error) {
	if h.decoded == h.rebuildEvery {
		if err := h.code.rebuild(h.frequencies); err != nil {
			return 0, err
		}
		for index, frequency := range h.frequencies {
			h.frequencies[index] = frequency/2 + 1
		}
		h.decoded = 0
	}
	symbol, err := h.code.decode(reader)
	if err != nil {
		return 0, err
	}
	h.frequencies[symbol]++
	h.decoded++
	return symbol, nil
}
