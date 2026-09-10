package msdelta

import (
	"errors"
	"fmt"
	"sort"
)

const (
	intFormatSymbols = 252
	intFormatHalf    = intFormatSymbols / 2
	maxRiftEntries   = 1 << 20
)

// riftTable is a piecewise-constant displacement map. Each entry starts a
// segment where source coordinates are translated to target coordinates.
type riftTable struct {
	entries []riftEntry
}

type riftEntry struct {
	source int64
	target int64
}

type intFormat struct {
	tree *huffman
}

func readRiftTable(bits *bitReader) (riftTable, error) {
	present, err := bits.read(1)
	if err != nil {
		return riftTable{}, err
	}
	if present == 0 {
		return riftTable{}, nil
	}
	sourceFormat, err := readIntFormat(bits)
	if err != nil {
		return riftTable{}, fmt.Errorf("source integer format: %w", err)
	}
	targetFormat, err := readIntFormat(bits)
	if err != nil {
		return riftTable{}, fmt.Errorf("target integer format: %w", err)
	}
	return readRiftWithFormats(bits, sourceFormat, targetFormat)
}

func readRiftWithFormats(bits *bitReader, sourceFormat, targetFormat *intFormat) (riftTable, error) {
	count, err := bits.number64()
	if err != nil || count < 0 || count > maxRiftEntries {
		return riftTable{}, errors.New("invalid rift entry count")
	}
	entries := make([]riftEntry, 0, int(count))
	var source, displacement int64
	for range int(count) {
		delta, err := sourceFormat.read(bits)
		if err != nil {
			return riftTable{}, fmt.Errorf("source delta: %w", err)
		}
		source += delta
		delta, err = targetFormat.read(bits)
		if err != nil {
			return riftTable{}, fmt.Errorf("target delta: %w", err)
		}
		displacement += delta
		entries = append(entries, riftEntry{source: source, target: source + displacement})
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].source < entries[j].source })
	return riftTable{entries: entries}, nil
}

func readIntFormat(bits *bitReader) (*intFormat, error) {
	positive, err := bits.read(8)
	if err != nil {
		return nil, err
	}
	negative, err := bits.read(8)
	if err != nil {
		return nil, err
	}
	defaultCount, err := bits.read(8)
	if err != nil {
		return nil, err
	}
	if positive > intFormatHalf || negative > intFormatHalf || int(defaultCount) > intFormatSymbols-int(positive)-int(negative) {
		return nil, errors.New("integer format mode is out of range")
	}
	lengths := make([]byte, intFormatSymbols)
	for index := range int(positive) {
		value, err := bits.read(4)
		if err != nil {
			return nil, err
		}
		lengths[index] = byte(value + 1)
	}
	for index := range int(negative) {
		value, err := bits.read(4)
		if err != nil {
			return nil, err
		}
		lengths[intFormatHalf+index] = byte(value + 1)
	}
	value, err := bits.read(4)
	if err != nil {
		return nil, err
	}
	defaultLength := byte(value + 1)
	length := defaultLength
	remaining := int(defaultCount)
	for index := int(positive); index < intFormatHalf; index++ {
		if remaining == 0 {
			length--
			remaining = intFormatSymbols - int(positive) - int(negative) - index
		}
		lengths[index] = length
		remaining--
	}
	length = defaultLength
	remaining = max(0, int(defaultCount)-(intFormatHalf-int(positive)))
	for index := intFormatHalf + int(negative); index < intFormatSymbols; index++ {
		if remaining == 0 {
			length--
			remaining = intFormatHalf - (index - intFormatHalf)
		}
		lengths[index] = length
		remaining--
	}
	tree, err := newHuffman(lengths, 16)
	if err != nil {
		return nil, fmt.Errorf("integer Huffman (positive=%d negative=%d default=%d length=%d): %w", positive, negative, defaultCount, defaultLength, err)
	}
	return &intFormat{tree: tree}, nil
}

func (format *intFormat) read(bits *bitReader) (int64, error) {
	symbol, err := format.tree.decode(bits)
	if err != nil {
		return 0, err
	}
	negative := symbol >= intFormatHalf
	if negative {
		symbol -= intFormatHalf
	}
	var value int64
	if symbol <= 3 {
		value = int64(symbol)
	} else {
		extraBits := uint(symbol>>1) - 1
		base := int64(symbol&1) + 2
		extra, err := bits.read(extraBits)
		if err != nil {
			return 0, err
		}
		value = base<<extraBits | int64(extra)
	}
	if negative {
		return ^value, nil
	}
	return value, nil
}

// displacement returns the offset active at a source coordinate. Rift tables
// are cyclic: coordinates before the first stored breakpoint use the final
// segment's displacement. This matters for PE instruction preprocessing,
// where disassembling embedded data can produce a signed relative target below
// the first RVA breakpoint.
func (rift riftTable) displacement(source int64) int64 {
	if len(rift.entries) == 0 {
		return 0
	}
	index := sort.Search(len(rift.entries), func(i int) bool { return rift.entries[i].source > source })
	if index == 0 {
		entry := rift.entries[len(rift.entries)-1]
		return entry.target - entry.source
	}
	entry := rift.entries[index-1]
	return entry.target - entry.source
}

func (rift riftTable) mapForward(source int64) int64 {
	return source + rift.displacement(source)
}

func (rift riftTable) segment(source int64) (mapped, end int64) {
	index := sort.Search(len(rift.entries), func(i int) bool { return rift.entries[i].source > source })
	if index == 0 {
		mapped = source
	} else {
		entry := rift.entries[index-1]
		mapped = source + entry.target - entry.source
	}
	end = int64(^uint64(0) >> 1)
	if index < len(rift.entries) {
		end = rift.entries[index].source
	}
	return mapped, end
}

func (rift riftTable) wrappedSegment(source int64) (offset, end int64) {
	if len(rift.entries) == 0 {
		return 0, int64(^uint64(0) >> 1)
	}
	index := sort.Search(len(rift.entries), func(i int) bool { return rift.entries[i].source > source })
	if index == 0 {
		entry := rift.entries[len(rift.entries)-1]
		return entry.target - entry.source, rift.entries[0].source - 1
	}
	entry := rift.entries[index-1]
	end = int64(^uint64(0) >> 1)
	if index < len(rift.entries) {
		end = rift.entries[index].source - 1
	}
	return entry.target - entry.source, end
}

// multiply composes two piecewise displacement maps: b(rift(x)).
func (rift riftTable) multiply(b riftTable) riftTable {
	if len(rift.entries) == 0 {
		return b
	}
	if len(b.entries) == 0 {
		return rift
	}
	result := riftTable{}
	a := rift.entries
	first := a[0].source
	if first != int64(-1<<63) {
		last := a[len(a)-1]
		lastOffset := last.target - last.source
		image := int64(-1<<63) + lastOffset
		bOffset, bEnd := b.wrappedSegment(image)
		source := int64(-1 << 63)
		result.entries = append(result.entries, riftEntry{source: source, target: image + bOffset})
		region := uint64(first - 1 - source)
		step := uint64(bEnd - image)
		for step < region {
			source += int64(step) + 1
			image = bEnd + 1
			bOffset, bEnd = b.wrappedSegment(image)
			result.entries = append(result.entries, riftEntry{source: source, target: image + bOffset})
			region = uint64(first - 1 - source)
			step = uint64(bEnd - image)
		}
	}
	for index, entry := range a {
		segmentEnd := int64(^uint64(0) >> 1)
		if index+1 < len(a) {
			if a[index+1].source == entry.source {
				continue
			}
			segmentEnd = a[index+1].source - 1
		}
		source, image := entry.source, entry.target
		bOffset, bEnd := b.wrappedSegment(image)
		result.entries = append(result.entries, riftEntry{source: source, target: image + bOffset})
		for uint64(bEnd-image) < uint64(segmentEnd-source) {
			source += bEnd - image + 1
			image = bEnd + 1
			bOffset, bEnd = b.wrappedSegment(image)
			result.entries = append(result.entries, riftEntry{source: source, target: image + bOffset})
		}
	}
	sort.SliceStable(result.entries, func(i, j int) bool { return result.entries[i].source < result.entries[j].source })
	return result
}

// reverse constructs the inverse displacement map while preserving the
// defined precedence of overlapping image ranges and the continuation across
// gaps. It operates on interval boundaries rather than enumerating bytes.
func (rift riftTable) reverse() riftTable {
	n := len(rift.entries)
	if n == 0 {
		return riftTable{}
	}
	allSame := true
	for index := 1; index < n; index++ {
		allSame = allSame && rift.entries[index].source == rift.entries[0].source
	}
	if allSame {
		entry := rift.entries[0]
		return riftTable{entries: []riftEntry{{source: 0, target: entry.target - entry.source}}}
	}
	intervalStart := make([]int64, 2*n)
	intervalEnd := make([]int64, 2*n)
	intervalCount := 0
	result := riftTable{}
	firstPositive := 0
	for firstPositive < n && rift.entries[firstPositive].source <= 0 {
		firstPositive++
	}
	if firstPositive == 0 {
		firstPositive = n
	}
	stop := firstPositive - 1
	sourceCursor := int64(0)
	boundary := 0
	if firstPositive < n {
		boundary = firstPositive
	}
	active := stop
	for {
		for {
			offset := rift.entries[active].target - rift.entries[active].source
			endSegment := boundary
			span := rift.entries[boundary].source - sourceCursor
			imageStart := offset + sourceCursor
			if imageStart != int64(-1<<63) {
				clamped := int64(-1<<63) - offset - sourceCursor
				if uint64(clamped) < uint64(span) {
					span = clamped
				}
			}
			if span != 0 {
				imageEnd := imageStart + span
				firstOverlap := 0
				for firstOverlap < intervalCount && imageStart > intervalEnd[firstOverlap] && intervalEnd[firstOverlap] != int64(-1<<63) {
					firstOverlap++
				}
				insertAt, overlapEnd := firstOverlap, firstOverlap
				newEnd := imageEnd
				if firstOverlap < intervalCount {
					for overlapEnd < intervalCount {
						key := intervalStart[overlapEnd]
						if imageEnd != int64(-1<<63) && imageEnd < key {
							break
						}
						overlapEnd++
					}
					if firstOverlap == overlapEnd {
						result.entries = append(result.entries, riftEntry{source: imageStart, target: sourceCursor})
						replaceReverseInterval(intervalStart, intervalEnd, &intervalCount, insertAt, overlapEnd, imageStart, newEnd)
					} else {
						mergedStart := imageStart
						if imageStart < intervalStart[firstOverlap] {
							result.entries = append(result.entries, riftEntry{source: imageStart, target: sourceCursor})
						} else {
							mergedStart = intervalStart[firstOverlap]
						}
						newEnd = offset
						if insertAt < overlapEnd-1 {
							for index := firstOverlap; index < overlapEnd-1; index++ {
								point := intervalEnd[index]
								result.entries = append(result.entries, riftEntry{source: point, target: point - newEnd})
							}
							insertAt = firstOverlap
						}
						lastEnd := intervalEnd[overlapEnd-1]
						newEnd = lastEnd
						if lastEnd != int64(-1<<63) && (imageEnd == int64(-1<<63) || lastEnd < imageEnd) {
							result.entries = append(result.entries, riftEntry{source: lastEnd, target: lastEnd - offset})
							newEnd = imageEnd
						}
						replaceReverseInterval(intervalStart, intervalEnd, &intervalCount, insertAt, overlapEnd, mergedStart, newEnd)
					}
				} else {
					result.entries = append(result.entries, riftEntry{source: imageStart, target: sourceCursor})
					replaceReverseInterval(intervalStart, intervalEnd, &intervalCount, insertAt, overlapEnd, imageStart, newEnd)
				}
			}
			sourceCursor += span
			if sourceCursor == rift.entries[endSegment].source {
				break
			}
		}
		active = boundary
		if stop == boundary {
			break
		}
		boundary++
		if boundary == n {
			boundary = 0
		}
	}
	sort.SliceStable(result.entries, func(i, j int) bool { return result.entries[i].source < result.entries[j].source })
	filtered := result.entries[:0]
	for _, entry := range result.entries {
		if entry.source == int64(-1<<63) || entry.target == int64(-1<<63) {
			continue
		}
		if len(filtered) != 0 && filtered[len(filtered)-1].source == entry.source {
			filtered[len(filtered)-1] = entry
		} else {
			filtered = append(filtered, entry)
		}
	}
	result.entries = filtered
	return result
}

func replaceReverseInterval(starts, ends []int64, count *int, insertAt, overlapEnd int, start, end int64) {
	if insertAt == overlapEnd {
		copy(starts[insertAt+1:*count+1], starts[insertAt:*count])
		copy(ends[insertAt+1:*count+1], ends[insertAt:*count])
	} else if insertAt+1 != overlapEnd && overlapEnd < *count {
		copy(starts[insertAt+1:], starts[overlapEnd:*count])
		copy(ends[insertAt+1:], ends[overlapEnd:*count])
	}
	*count += insertAt - overlapEnd + 1
	starts[insertAt], ends[insertAt] = start, end
}
