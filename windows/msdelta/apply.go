package msdelta

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/tinyrange/trex/compression/lzms"
)

const (
	mainSymbols    = 0x258
	lengthSymbols  = 0x100
	alignedSymbols = 0x10
	allCodeLengths = mainSymbols + lengthSymbols + alignedSymbols
)

type codeSet struct {
	start                 uint64
	main, length, aligned *huffman
}

// PatchMatchInfo describes one decoded patch match overlapping an inspected
// target range. CombinedStart uses the virtual source-plus-target history
// coordinate space used by the patch decoder; literals report -1.
type PatchMatchInfo struct {
	Kind                    string
	TargetStart, TargetEnd  int
	CombinedStart, Distance int64
	RiftOffset, RiftNext    int64
	SourceRiftOffset        int64
	SourceRiftNext          int64
}

// PatchRangeInfo is a bounded view of the intermediate patch output and the
// compressed matches which produced it. Decoded is taken before PE restoration.
type PatchRangeInfo struct {
	Start, End   int
	Decoded      []byte
	Matches      []PatchMatchInfo
	PETransforms []PETransformInfo
}

type patchTraceCollector struct {
	start, end int
	matches    []PatchMatchInfo
}

func (trace *patchTraceCollector) add(match deltaMatch, targetStart int, combinedStart, distance, riftOffset int64) {
	targetEnd := targetStart + int(match.length)
	if targetStart >= trace.end || targetEnd <= trace.start {
		return
	}
	overlapStart, overlapEnd := max(targetStart, trace.start), min(targetEnd, trace.end)
	if combinedStart >= 0 {
		combinedStart += int64(overlapStart - targetStart)
	}
	kind := [...]string{"literal", "source", "full_source", "lru", "destination"}[match.kind]
	trace.matches = append(trace.matches, PatchMatchInfo{
		Kind: kind, TargetStart: overlapStart, TargetEnd: overlapEnd,
		CombinedStart: combinedStart, Distance: distance, RiftOffset: riftOffset,
	})
}

func (trace *patchTraceCollector) addSource(match deltaMatch, targetStart int, combinedStart, distance int64, rift riftTable) {
	before := len(trace.matches)
	trace.add(match, targetStart, combinedStart, distance, 0)
	if len(trace.matches) == before {
		return
	}
	entry := &trace.matches[len(trace.matches)-1]
	targetPosition := entry.CombinedStart + entry.Distance
	targetOffset, targetNext := patchRiftSegment(rift, targetPosition)
	sourceOffset, sourceNext := patchRiftSegment(rift, entry.CombinedStart)
	entry.RiftOffset = targetOffset
	entry.RiftNext = targetNext
	entry.SourceRiftOffset = sourceOffset
	entry.SourceRiftNext = sourceNext
}

func (trace *patchTraceCollector) addFullSource(targetStart, sourceLength int, length uint32, rift riftTable) {
	targetEnd := targetStart + int(length)
	for cursor := targetStart; cursor < targetEnd; {
		position := int64(sourceLength + cursor)
		offset, next := patchRiftSegment(rift, position)
		segmentEnd := targetEnd
		if next != int64(^uint64(0)>>1) && next-position < int64(segmentEnd-cursor) {
			segmentEnd = cursor + int(next-position)
		}
		if segmentEnd <= cursor {
			break
		}
		segment := deltaMatch{kind: matchFullSource, length: uint32(segmentEnd - cursor)}
		trace.add(segment, cursor, position+offset, -offset, offset)
		cursor = segmentEnd
	}
}

// InspectPatchRangeBounded decodes a PA30/PA31 patch without hash enforcement
// and returns only a caller-selected range plus its producing match records.
// It is intended for format investigation, not construction.
func InspectPatchRangeBounded(source, delta []byte, start, end int, maximumTargetSize uint64) (PatchRangeInfo, error) {
	return inspectPatchRangeBounded(source, delta, start, end, maximumTargetSize, true)
}

// InspectPreparedSourceRange returns a bounded copy of the source bytes after
// preprocessing, before patch matches are applied. It verifies any declared
// source hash but does not reconstruct or verify a target. Inputs are unchanged.
func InspectPreparedSourceRange(source, delta []byte, start, end int) ([]byte, error) {
	if start < 0 || end <= start || end > len(source) {
		return nil, errors.New("msdelta: invalid prepared-source inspection range")
	}
	header, err := Parse(delta)
	if err != nil {
		return nil, err
	}
	if len(header.ExtensionHash) != 0 {
		if err := verifyHash("source", source, header.HashAlgorithm, header.ExtensionHash); err != nil {
			return nil, err
		}
	}
	if len(header.Preprocess) != 0 {
		source, _, err = preparePE(source, header.Preprocess, header.Flags)
		if err != nil {
			return nil, err
		}
	}
	return append([]byte(nil), source[start:end]...), nil
}

// InspectPatchRangeBytesBounded omits PE transform-event collection when only
// reconstructed bytes are needed for a broad comparison. For LZMS-backed
// patches it returns bytes without match provenance, before PE restoration.
func InspectPatchRangeBytesBounded(source, delta []byte, start, end int, maximumTargetSize uint64) (PatchRangeInfo, error) {
	return inspectPatchRangeBounded(source, delta, start, end, maximumTargetSize, false)
}

func inspectPatchRangeBounded(source, delta []byte, start, end int, maximumTargetSize uint64, includeTransforms bool) (PatchRangeInfo, error) {
	header, err := Parse(delta)
	if err != nil {
		return PatchRangeInfo{}, err
	}
	if header.TargetSize > maximumTargetSize {
		return PatchRangeInfo{}, fmt.Errorf("msdelta: target size %d exceeds limit %d", header.TargetSize, maximumTargetSize)
	}
	if start < 0 || end <= start || uint64(end) > header.TargetSize {
		return PatchRangeInfo{}, errors.New("msdelta: invalid patch inspection range")
	}
	if len(header.ExtensionHash) != 0 {
		if err := verifyHash("source", source, header.HashAlgorithm, header.ExtensionHash); err != nil {
			return PatchRangeInfo{}, err
		}
	}
	var preprocess *pePreprocess
	var transformTrace *peTransformTrace
	if includeTransforms {
		transformTrace = &peTransformTrace{}
	}
	if len(header.Preprocess) != 0 {
		source, preprocess, err = preparePETraced(source, header.Preprocess, header.Flags, transformTrace)
		if err != nil {
			return PatchRangeInfo{}, err
		}
	}
	if len(header.Patch) >= 4 && binary.LittleEndian.Uint32(header.Patch[:4]) == lzms.CompressionAPIMagic {
		if includeTransforms {
			return PatchRangeInfo{}, errors.New("msdelta: LZMS match tracing is not supported; use byte-only inspection")
		}
		target, _, _, err := decodeLZMSPatch(source, header.Patch, header.TargetSize, maximumTargetSize)
		if err != nil {
			return PatchRangeInfo{}, err
		}
		return PatchRangeInfo{Start: start, End: end, Decoded: append([]byte(nil), target[start:end]...)}, nil
	}
	trace := &patchTraceCollector{start: start, end: end}
	target, err := decodePatchMappedTraced(source, header.Patch, header.TargetSize, preprocess, trace)
	if err != nil {
		return PatchRangeInfo{}, err
	}
	transforms := make([]PETransformInfo, 0)
	if transformTrace != nil {
		type sourceInterval struct{ start, end int64 }
		intervals := make([]sourceInterval, 0, len(trace.matches))
		for _, match := range trace.matches {
			if match.CombinedStart < 0 || match.CombinedStart >= int64(len(source)) {
				continue
			}
			end := min(int64(len(source)), match.CombinedStart+int64(match.TargetEnd-match.TargetStart))
			if end > match.CombinedStart {
				intervals = append(intervals, sourceInterval{start: match.CombinedStart, end: end})
			}
		}
		sort.Slice(intervals, func(i, j int) bool { return intervals[i].start < intervals[j].start })
		merged := intervals[:0]
		for _, interval := range intervals {
			if len(merged) == 0 || interval.start > merged[len(merged)-1].end {
				merged = append(merged, interval)
			} else if interval.end > merged[len(merged)-1].end {
				merged[len(merged)-1].end = interval.end
			}
		}
		for _, event := range transformTrace.events {
			index := sort.Search(len(merged), func(i int) bool { return merged[i].end > int64(event.RawStart) })
			if index < len(merged) && merged[index].start < int64(event.RawEnd) {
				transforms = append(transforms, event)
			}
		}
	}
	return PatchRangeInfo{
		Start: start, End: end,
		Decoded: append([]byte(nil), target[start:end]...), Matches: trace.matches,
		PETransforms: transforms,
	}, nil
}

// Apply reconstructs and verifies the target represented by a PA30 or PA31
// delta. Input must begin at the PA signature, without a PSF checksum prefix.
func Apply(source, delta []byte) ([]byte, error) {
	return applyBounded(source, delta, ^uint64(0))
}

// ApplyBounded reconstructs and verifies a target only when its declared size
// does not exceed maximumTargetSize. The bound is checked before preprocessing
// or target allocation.
func ApplyBounded(source, delta []byte, maximumTargetSize uint64) ([]byte, error) {
	return applyBounded(source, delta, maximumTargetSize)
}

// ApplyPSFRecordBounded verifies the four-byte PSF record checksum before
// applying its enclosed PA30/PA31 delta.
func ApplyPSFRecordBounded(source, record []byte, maximumTargetSize uint64) ([]byte, error) {
	if _, err := ParsePSFRecord(record); err != nil {
		return nil, err
	}
	return applyBounded(source, record[4:], maximumTargetSize)
}

func applyBounded(source, delta []byte, maximumTargetSize uint64) ([]byte, error) {
	target, header, err := reconstructBounded(source, delta, maximumTargetSize)
	if err != nil {
		return nil, err
	}
	if err := verifyHash("target", target, header.HashAlgorithm, header.TargetHash); err != nil {
		prefix := header.Patch
		if len(prefix) > 4 {
			prefix = prefix[:4]
		}
		return target, fmt.Errorf("%w (file-type-set=%#x file-type=%#x flags=%#x preprocess=%d patch-prefix=%x)", err, header.FileTypeSet, header.FileType, header.Flags, len(header.Preprocess), prefix)
	}
	return target, nil
}

func reconstruct(source, delta []byte) ([]byte, *Header, error) {
	return reconstructBounded(source, delta, ^uint64(0))
}

func reconstructBounded(source, delta []byte, maximumTargetSize uint64) ([]byte, *Header, error) {
	header, err := Parse(delta)
	if err != nil {
		return nil, nil, err
	}
	if header.TargetSize > maximumTargetSize {
		return nil, header, fmt.Errorf("msdelta: target size %d exceeds limit %d", header.TargetSize, maximumTargetSize)
	}
	if len(header.ExtensionHash) != 0 {
		if err := verifyHash("source", source, header.HashAlgorithm, header.ExtensionHash); err != nil {
			return nil, nil, err
		}
	}
	originalSource := source
	var preprocess *pePreprocess
	if len(header.Preprocess) != 0 {
		source, preprocess, err = preparePE(source, header.Preprocess, header.Flags)
		if err != nil {
			return nil, header, fmt.Errorf("msdelta: preprocess file-type-set=%#x file-type=%#x flags=%#x preprocess=%d: %w", header.FileTypeSet, header.FileType, header.Flags, len(header.Preprocess), err)
		}
	}
	isLZMS := len(header.Patch) >= 4 && binary.LittleEndian.Uint32(header.Patch[:4]) == lzms.CompressionAPIMagic
	nestedLZMSDelta := false
	lzmsPayloadSize := 0
	var target []byte
	if isLZMS {
		target, nestedLZMSDelta, lzmsPayloadSize, err = decodeLZMSPatch(source, header.Patch, header.TargetSize, maximumTargetSize)
		if err != nil {
			return nil, header, err
		}
	} else {
		target, err = decodePatchMapped(source, header.Patch, header.TargetSize, preprocess)
		if err != nil {
			prefix := header.Patch
			if len(prefix) > 4 {
				prefix = prefix[:4]
			}
			return nil, nil, fmt.Errorf("msdelta: decode file-type-set=%#x file-type=%#x flags=%#x patch-prefix=%x: %w", header.FileTypeSet, header.FileType, header.Flags, prefix, err)
		}
	}
	// A PE preprocessing stream describes how to normalize and map the source;
	// it does not guarantee that the reconstructed target is also a PE. Windows
	// update uses cross-type deltas (for example, a PE basis that produces XML),
	// which retain the source transform but have no PE fields to restore.
	// The x86 E8 pass must precede structural restoration because that step can
	// rebuild the PE checksum, which covers the restored relative operands.
	if uint64(header.Flags)&peTransformX86E8 != 0 {
		restoreX86E8(target)
	}
	if preprocess != nil && bytes.HasPrefix(target, []byte("MZ")) {
		if nestedLZMSDelta {
			err = preprocess.restore(target)
		} else if isLZMS {
			err = restorePETimestamps(originalSource, target, preprocess.prefix.timestamp)
		}
		if err != nil {
			return nil, header, fmt.Errorf("msdelta: postprocess file-type-set=%#x file-type=%#x flags=%#x preprocess=%d lzms=%t nested=%t payload=%d target=%d: %w", header.FileTypeSet, header.FileType, header.Flags, len(header.Preprocess), isLZMS, nestedLZMSDelta, lzmsPayloadSize, header.TargetSize, err)
		}
	}
	return target, header, nil
}

func decodePatch(source, patch []byte, targetSize uint64) ([]byte, error) {
	return decodePatchMapped(source, patch, targetSize, nil)
}

func decodeLZMSPatch(source, patch []byte, targetSize, maximumTargetSize uint64) ([]byte, bool, int, error) {
	payload, err := lzms.DecompressContainer(patch, maximumTargetSize)
	if err != nil {
		return nil, false, 0, fmt.Errorf("msdelta: LZMS container: %w", err)
	}
	if uint64(len(payload)) == targetSize {
		return payload, false, len(payload), nil
	}
	target, err := applyBSDiff(source, targetSize, payload)
	if err != nil {
		return nil, true, len(payload), fmt.Errorf("msdelta: LZMS binary delta: %w", err)
	}
	return target, true, len(payload), nil
}

func decodePatchMapped(source, patch []byte, targetSize uint64, preprocess *pePreprocess) ([]byte, error) {
	return decodePatchMappedTraced(source, patch, targetSize, preprocess, nil)
}

func decodePatchMappedTraced(source, patch []byte, targetSize uint64, preprocess *pePreprocess, trace *patchTraceCollector) ([]byte, error) {
	if targetSize > uint64(int(^uint(0)>>1)) {
		return nil, errors.New("msdelta: target is too large")
	}
	bits, err := newBitReader(patch)
	if err != nil {
		return nil, fmt.Errorf("msdelta: patch bitstream: %w", err)
	}
	baseRift, err := readRiftTable(bits)
	if err != nil {
		return nil, fmt.Errorf("msdelta: base rift table: %w", err)
	}
	return decodePatchBodyTraced(source, bits, targetSize, preprocess, baseRift, trace)
}

func decodePatchBody(source []byte, bits *bitReader, targetSize uint64, preprocess *pePreprocess, baseRift riftTable) ([]byte, error) {
	return decodePatchBodyTraced(source, bits, targetSize, preprocess, baseRift, nil)
}

func decodePatchBodyTraced(source []byte, bits *bitReader, targetSize uint64, preprocess *pePreprocess, baseRift riftTable, trace *patchTraceCollector) ([]byte, error) {
	sets, err := readCodeSets(bits)
	if err != nil {
		return nil, err
	}

	// The patch rift is already expressed in the decompressor's virtual
	// source-plus-target coordinate space. PE preprocessing instead produces a
	// target-file-offset -> source-file-offset map, so fold its source
	// breakpoints past the prepended reference before merging the two tables.
	// The final boundary is the implicit identity mapping used by raw patches:
	// at virtual position len(source)+targetOffset, copy from targetOffset.
	rift := riftTable{entries: append([]riftEntry(nil), baseRift.entries...)}
	if preprocess != nil {
		for _, entry := range preprocess.targetToSource.entries {
			rift.entries = append(rift.entries, riftEntry{
				source: int64(len(source)) + entry.source,
				target: entry.target,
			})
		}
	}
	rift.entries = append(rift.entries, riftEntry{source: int64(len(source)), target: 0})
	sort.SliceStable(rift.entries, func(i, j int) bool { return rift.entries[i].source < rift.entries[j].source })

	target := make([]byte, 0, int(targetSize))
	lru := [3]int64{}
	setIndex := 0
	for uint64(len(target)) < targetSize {
		// Compression parameter boundaries are in the virtual stream formed by
		// prepending the reference to the output. They are not relative to the
		// first boundary or to the target alone.
		position := uint64(len(source)) + uint64(len(target))
		for setIndex+1 < len(sets) && position >= sets[setIndex+1].start {
			setIndex++
		}
		match, err := decodeMatch(bits, sets[setIndex])
		if err != nil {
			return nil, fmt.Errorf("msdelta: match at target offset %#x: %w", len(target), err)
		}
		if uint64(match.length) > targetSize-uint64(len(target)) {
			return nil, fmt.Errorf("msdelta: match length %d exceeds target at %#x", match.length, len(target))
		}
		switch match.kind {
		case matchLiteral:
			if trace != nil {
				trace.add(match, len(target), -1, 0, 0)
			}
			target = append(target, byte(match.value))
		case matchSource:
			position := int64(len(source) + len(target))
			offset, _ := patchRiftSegment(rift, position)
			start := position + offset - int64(int32(match.value))
			if start < 0 || start >= int64(len(source)+len(target)) {
				return nil, fmt.Errorf("msdelta: source match at target offset %#x: start %#x is invalid", len(target), start)
			}
			// Slots 0-2 encode a fixed signed distance for the complete match.
			// Rift breakpoints select that distance at the match start but do not
			// split the copy. Only matchFullSource re-anchors at each breakpoint.
			updateLRU(&lru, position-start)
			if trace != nil {
				trace.addSource(match, len(target), start, position-start, rift)
			}
			if err := appendCombinedMatch(&target, source, int(start), match.length); err != nil {
				return nil, fmt.Errorf("msdelta: source match at target offset %#x: %w", len(target), err)
			}
		case matchFullSource:
			position := int64(len(source) + len(target))
			offset, _ := patchRiftSegment(rift, position)
			updateLRU(&lru, -offset)
			if trace != nil {
				trace.addFullSource(len(target), len(source), match.length, rift)
			}
			if err := appendRiftedSource(&target, source, match.length, rift); err != nil {
				return nil, fmt.Errorf("msdelta: full-source match of length %#x at target offset %#x: %w", match.length, len(target), err)
			}
		case matchDestination:
			offset := int64(match.value)
			if offset == 0 || uint64(offset) > uint64(len(source))+uint64(len(target)) {
				return nil, fmt.Errorf("msdelta: destination offset %#x is invalid at target offset %#x", offset, len(target))
			}
			updateLRU(&lru, offset)
			if trace != nil {
				trace.add(match, len(target), int64(len(source)+len(target))-offset, offset, 0)
			}
			if err := appendHistoryMatch(&target, source, int(offset), match.length); err != nil {
				return nil, err
			}
		case matchLRU:
			index := int(match.value)
			offset := lru[index]
			if offset == 0 || uint64(offset) > uint64(len(source))+uint64(len(target)) {
				return nil, fmt.Errorf("msdelta: LRU offset %#x is invalid at target offset %#x", offset, len(target))
			}
			updateLRU(&lru, offset)
			if trace != nil {
				trace.add(match, len(target), int64(len(source)+len(target))-offset, offset, 0)
			}
			if err := appendHistoryMatch(&target, source, int(offset), match.length); err != nil {
				return nil, err
			}
		}
	}
	return target, nil
}

// patchRiftSegment returns the displacement active at position and the first
// position of the following segment. Rift lookup wraps below the first entry;
// the implicit source boundary ensures ordinary decoding starts in a defined
// segment.
func patchRiftSegment(rift riftTable, position int64) (offset, next int64) {
	mapped, end := rift.wrappedSegment(position)
	offset = mapped
	if end == int64(^uint64(0)>>1) {
		return offset, end
	}
	return offset, end + 1
}

func appendRiftedSource(target *[]byte, source []byte, length uint32, rift riftTable) error {
	remaining := int(length)
	for remaining > 0 {
		position := int64(len(source) + len(*target))
		offset, next := patchRiftSegment(rift, position)
		start := position + offset
		span := int64(remaining)
		if next != int64(^uint64(0)>>1) && next-position < span {
			span = next - position
		}
		if span <= 0 || start < 0 || start > int64(^uint(0)>>1) {
			return fmt.Errorf("rifted source match at %#x has invalid length %#x", start, span)
		}
		if err := appendCombinedMatch(target, source, int(start), uint32(span)); err != nil {
			return err
		}
		remaining -= int(span)
	}
	return nil
}

func appendCombinedMatch(target *[]byte, source []byte, start int, length uint32) error {
	for range length {
		if start < 0 || start >= len(source)+len(*target) {
			return errors.New("combined source match ran past available history")
		}
		if start < len(source) {
			*target = append(*target, source[start])
		} else {
			targetOffset := start - len(source)
			*target = append(*target, (*target)[targetOffset])
		}
		start++
	}
	return nil
}

func appendHistoryMatch(target *[]byte, source []byte, offset int, length uint32) error {
	historyLength := len(source) + len(*target)
	if offset <= 0 || offset > historyLength {
		return errors.New("msdelta: invalid history match")
	}
	return appendCombinedMatch(target, source, historyLength-offset, length)
}

func updateLRU(lru *[3]int64, value int64) {
	if lru[0] == value {
		return
	}
	if lru[1] != value {
		lru[2] = lru[1]
	}
	lru[1] = lru[0]
	lru[0] = value
}

func readCodeSets(bits *bitReader) ([]codeSet, error) {
	isDefault, err := bits.read(1)
	if err != nil {
		return nil, fmt.Errorf("msdelta: compression parameters: %w", err)
	}
	if isDefault != 0 {
		set, err := makeCodeSet(0, append(append(defaultHuffmanLengths(mainSymbols), defaultHuffmanLengths(lengthSymbols)...), defaultHuffmanLengths(alignedSymbols)...))
		if err != nil {
			return nil, err
		}
		return []codeSet{set}, nil
	}
	count, err := bits.number32()
	if err != nil || count == 0 || count > 1<<20 {
		return nil, errors.New("msdelta: invalid compression parameter block count")
	}
	starts := make([]uint64, count)
	for index := range starts {
		delta, err := bits.number64()
		if err != nil || delta < 0 {
			return nil, fmt.Errorf("msdelta: parameter block %d start: invalid delta", index)
		}
		if index > 0 {
			starts[index] = starts[index-1]
		}
		starts[index] += uint64(delta)
	}
	preLengths := make([]byte, 39)
	for index := range preLengths {
		value, err := bits.read(4)
		if err != nil {
			return nil, fmt.Errorf("msdelta: Huffman pre-tree: %w", err)
		}
		preLengths[index] = byte(value)
	}
	preTree, err := newHuffman(preLengths, 15)
	if err != nil {
		return nil, fmt.Errorf("msdelta: Huffman pre-tree: %w", err)
	}
	sets := make([]codeSet, count)
	previous := make([]byte, allCodeLengths)
	for index := range sets {
		lengths, err := readCodeLengths(bits, preTree, previous)
		if err != nil {
			return nil, fmt.Errorf("msdelta: parameter block %d: %w", index, err)
		}
		sets[index], err = makeCodeSet(starts[index], lengths)
		if err != nil {
			return nil, fmt.Errorf("msdelta: parameter block %d: %w", index, err)
		}
		previous = lengths
	}
	return sets, nil
}

func readCodeLengths(bits *bitReader, tree *huffman, previous []byte) ([]byte, error) {
	result := make([]byte, allCodeLengths)
	for index := 0; index < len(result); {
		symbol, err := tree.decode(bits)
		if err != nil {
			return nil, err
		}
		switch {
		case symbol < 17:
			result[index] = byte(symbol)
			index++
		case symbol < 20:
			value := int(previous[index]) + symbol - 16
			if value > 16 {
				return nil, errors.New("Huffman length overflow")
			}
			result[index] = byte(value)
			index++
		case symbol < 23:
			value := int(previous[index]) - (symbol - 19)
			if value < 0 {
				return nil, errors.New("Huffman length underflow")
			}
			result[index] = byte(value)
			index++
		case symbol < 39:
			code := (symbol - 23) & 7
			length := code + 1
			if code >= 3 {
				extra, err := bits.read(uint(code - 1))
				if err != nil {
					return nil, err
				}
				length = 1<<(code-1) | int(extra)
			}
			if index+length > len(result) {
				return nil, errors.New("Huffman length run exceeds parameter block")
			}
			if symbol < 31 {
				if index == 0 {
					return nil, errors.New("Huffman fill run has no preceding length")
				}
				for run := 0; run < length; run++ {
					result[index+run] = result[index-1]
				}
			} else {
				copy(result[index:index+length], previous[index:index+length])
			}
			index += length
		default:
			return nil, errors.New("invalid Huffman pre-tree symbol")
		}
	}
	return result, nil
}

func makeCodeSet(start uint64, lengths []byte) (codeSet, error) {
	if len(lengths) != allCodeLengths {
		return codeSet{}, errors.New("invalid code-length count")
	}
	main, err := newHuffman(lengths[:mainSymbols], 16)
	if err != nil {
		return codeSet{}, fmt.Errorf("main Huffman tree: %w", err)
	}
	length, err := optionalHuffman(lengths[mainSymbols:mainSymbols+lengthSymbols], 16)
	if err != nil {
		return codeSet{}, fmt.Errorf("length Huffman tree: %w", err)
	}
	aligned, err := optionalHuffman(lengths[mainSymbols+lengthSymbols:], 16)
	if err != nil {
		return codeSet{}, fmt.Errorf("aligned Huffman tree: %w", err)
	}
	return codeSet{start: start, main: main, length: length, aligned: aligned}, nil
}

func optionalHuffman(lengths []byte, maximum int) (*huffman, error) {
	for _, length := range lengths {
		if length != 0 {
			return newHuffman(lengths, maximum)
		}
	}
	return nil, nil
}

type matchKind byte

const (
	matchLiteral matchKind = iota
	matchSource
	matchFullSource
	matchLRU
	matchDestination
)

type deltaMatch struct {
	kind   matchKind
	value  uint32
	length uint32
}

func decodeMatch(bits *bitReader, codes codeSet) (deltaMatch, error) {
	symbol, err := codes.main.decode(bits)
	if err != nil {
		return deltaMatch{}, err
	}
	if symbol < 256 {
		return deltaMatch{kind: matchLiteral, value: uint32(symbol), length: 1}, nil
	}
	symbol -= 256
	slot := uint32(symbol >> 3)
	lengthCode := uint32(symbol & 7)
	match := deltaMatch{}
	switch {
	case slot == 0:
		value, err := bits.read(14)
		if err != nil {
			return match, err
		}
		match.kind, match.value = matchSource, uint32(int32(value)-0x2000)
	case slot == 1:
		value, err := bits.read(16)
		if err != nil {
			return match, err
		}
		delta := int32(value) - 0x8000
		if delta < 0 {
			delta -= 0x2000
		} else {
			delta += 0x2000
		}
		match.kind, match.value = matchSource, uint32(delta)
	case slot == 2:
		value, err := bits.read(18)
		if err != nil {
			return match, err
		}
		delta := int32(value) - 0x20000
		if delta < 0 {
			delta -= 0xa000
		} else {
			delta += 0xa000
		}
		match.kind, match.value = matchSource, uint32(delta)
	case slot == 3:
		match.kind = matchFullSource
	case slot >= 4 && slot <= 6:
		match.kind, match.value = matchLRU, slot-4
	case slot >= 8 && slot <= 10:
		match.kind, match.value = matchDestination, slot-7
	default:
		if slot == 7 {
			prefix, err := bits.read(1)
			if err != nil {
				return match, err
			}
			if prefix == 0 {
				value, err := bits.read(2)
				if err != nil {
					return match, err
				}
				slot = 43 + uint32(value)
			} else {
				second, err := bits.read(1)
				if err != nil {
					return match, err
				}
				if second == 0 {
					value, err := bits.read(3)
					if err != nil {
						return match, err
					}
					slot = 47 + uint32(value)
				} else {
					value, err := bits.read(4)
					if err != nil {
						return match, err
					}
					slot = 55 + uint32(value)
				}
			}
		}
		if slot < 11 || slot > 70 {
			return match, fmt.Errorf("invalid match slot %d", slot)
		}
		verbatim := (slot - 9) >> 1
		top := uint32(2 | ((slot - 11) & 1))
		offset := top << verbatim
		if verbatim < 4 {
			value, err := bits.read(uint(verbatim))
			if err != nil {
				return match, err
			}
			offset |= uint32(value)
		} else {
			if verbatim > 4 {
				value, err := bits.read(uint(verbatim - 4))
				if err != nil {
					return match, err
				}
				offset |= uint32(value) << 4
			}
			if codes.aligned == nil {
				return match, errors.New("match requires an empty aligned Huffman tree")
			}
			aligned, err := codes.aligned.decode(bits)
			if err != nil {
				return match, err
			}
			offset |= uint32(aligned)
		}
		match.kind, match.value = matchDestination, offset
	}
	if lengthCode != 0 {
		match.length = lengthCode + 1
		return match, nil
	}
	if codes.length == nil {
		return match, errors.New("match requires an empty length Huffman tree")
	}
	lengthSymbol, err := codes.length.decode(bits)
	if err != nil {
		return match, err
	}
	if lengthSymbol != 0 {
		match.length = uint32(lengthSymbol + 8)
		return match, nil
	}
	longLength, err := bits.number8()
	if err != nil || longLength > uint64(^uint32(0)-8) {
		return match, errors.New("invalid long match length")
	}
	match.length = uint32(longLength + 8)
	return match, nil
}

func (r *bitReader) number8() (uint64, error) {
	zeros := uint(0)
	for {
		bit, err := r.read(1)
		if err != nil {
			return 0, err
		}
		if bit != 0 {
			break
		}
		zeros++
		if zeros >= 24 {
			return 0, errors.New("long length prefix is too large")
		}
	}
	length := zeros + 8
	value, err := r.read(length)
	if err != nil {
		return 0, err
	}
	return uint64(1)<<length | value, nil
}

func verifyHash(label string, data []byte, algorithm uint32, expected []byte) error {
	var actual []byte
	switch algorithm {
	case 0:
		if len(expected) == 0 {
			return nil
		}
	case 0x8003:
		digest := md5.Sum(data)
		actual = digest[:]
	case 0x8004:
		digest := sha1.Sum(data)
		actual = digest[:]
	case 0x800c:
		digest := sha256.Sum256(data)
		actual = digest[:]
	default:
		return fmt.Errorf("msdelta: unsupported target hash algorithm %#x", algorithm)
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("msdelta: %s hash mismatch: got %x, want %x", label, actual, expected)
	}
	return nil
}
