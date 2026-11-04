package msdelta

// PA31 playback framing was cross-checked against the MIT-licensed
// CaddyGlow/ms-delta reverse.rs implementation. See playback.LICENSE.

import (
	"errors"
	"fmt"

	"github.com/tinyrange/trex/compression/xpress"
)

// decodePlayback restores an earlier source from ordered copy, literal and
// byte-restoration records. It is not the forward PE transform pipeline.
func decodePlayback(source, patch []byte, size uint64) ([]byte, error) {
	return decodePlaybackTraced(source, patch, size, nil)
}

func decodePlaybackTraced(source, patch []byte, size uint64, trace *patchTraceCollector) ([]byte, error) {
	if size > uint64(int(^uint(0)>>1)) {
		return nil, errors.New("msdelta: playback target too large")
	}
	bits, err := newBitReader(patch)
	if err != nil {
		return nil, err
	}
	signature, err := bits.read(32)
	if err != nil || signature != 0x4d535250 {
		return nil, errors.New("msdelta: invalid playback signature")
	}
	version, err := bits.read(32)
	if err != nil || version != 1 {
		return nil, errors.New("msdelta: unsupported playback version")
	}
	output := make([]byte, int(size))
	tree, err := newHuffman(defaultHuffmanLengths(intFormatSymbols), 16)
	if err != nil {
		return nil, err
	}
	lengths := &intFormat{tree: tree}
	// Bound cumulative work, including repeated overlapping writes. The record
	// stream itself may be larger than the final image (deleted bytes).
	work := uint64(len(source)) + size + uint64(len(patch))
	if work > (^uint64(0)-1)/4 {
		return nil, errors.New("msdelta: playback work overflow")
	}
	work = work*4 + 1
	for !bits.atEnd() {
		record, err := bits.buffer()
		if err != nil {
			return nil, fmt.Errorf("msdelta: playback record: %w", err)
		}
		r, err := newBitReader(record)
		if err != nil {
			return nil, err
		}
		kind, err := r.read(32)
		if err != nil || kind > 2 {
			return nil, errors.New("msdelta: unsupported playback record kind")
		}
		version, err := r.read(32)
		if err != nil || version != 1 {
			return nil, errors.New("msdelta: unsupported playback record version")
		}
		var compressed uint64
		if kind == 1 {
			compressed, err = r.read(32)
			if err != nil {
				return nil, err
			}
		}
		// Large PE playback byte-restoration tables can exceed the forward
		// transform table limit. Bound their allocation to 128 MiB and work.
		entries, err := readRiftTableBounded(r, min(work, 8<<20))
		if err != nil {
			return nil, fmt.Errorf("msdelta: playback entries: %w", err)
		}
		if uint64(len(entries.entries))+1 > work {
			return nil, errors.New("msdelta: playback work limit")
		}
		work -= uint64(len(entries.entries)) + 1
		switch kind {
		case 0:
			for _, entry := range entries.entries {
				length, err := lengths.read(r)
				if err != nil {
					return nil, err
				}
				// Native playback clamps copy ranges at both ends. A negative signed
				// length denotes the corresponding unsigned value, hence the clamp.
				left, right := uint64(entry.source), uint64(entry.target)
				if left > size || right >= uint64(len(source)) {
					continue
				}
				n := min(uint64(length), size-left, uint64(len(source))-right)
				if n > work {
					return nil, errors.New("msdelta: playback work limit")
				}
				work -= n
				copy(output[left:left+n], source[right:right+n])
				tracePlayback(trace, "playback-copy", int(left), int(left+n), int64(right))
			}
		case 1:
			literal, err := r.buffer()
			if err != nil {
				return nil, err
			}
			// Calculate the exact decoded literal bound before allocating it.
			var total uint64
			for _, entry := range entries.entries {
				if entry.source < 0 || entry.target < 0 || uint64(entry.source) > size || uint64(entry.target) > size-uint64(entry.source) {
					return nil, errors.New("msdelta: playback literal target bounds")
				}
				if uint64(entry.target) > work-total {
					return nil, errors.New("msdelta: playback literal work limit")
				}
				total += uint64(entry.target)
			}
			if compressed != 0 {
				literal, err = xpress.DecompressContainer(literal, total)
				if err != nil {
					return nil, fmt.Errorf("msdelta: playback literals: %w", err)
				}
			}
			if uint64(len(literal)) != total {
				return nil, errors.New("msdelta: playback literal size mismatch")
			}
			position := int64(0)
			for _, entry := range entries.entries {
				copy(output[entry.source:entry.source+entry.target], literal[position:position+entry.target])
				tracePlayback(trace, "playback-literal", int(entry.source), int(entry.source+entry.target), -1)
				position += entry.target
			}
			work -= total
		case 2:
			// Byte fixes are replayed backwards, including duplicate positions.
			for i := len(entries.entries) - 1; i >= 0; i-- {
				entry := entries.entries[i]
				if entry.source < 0 || uint64(entry.source) >= size {
					return nil, errors.New("msdelta: playback byte bounds")
				}
				output[entry.source] = byte(entry.target)
				tracePlayback(trace, "playback-byte", int(entry.source), int(entry.source+1), -1)
			}
		}
		if !r.atEnd() {
			return nil, errors.New("msdelta: trailing playback record data")
		}
	}
	return output, nil
}

func tracePlayback(trace *patchTraceCollector, kind string, start, end int, source int64) {
	if trace == nil || start >= trace.end || end <= trace.start {
		return
	}
	left, right := max(start, trace.start), min(end, trace.end)
	if source >= 0 {
		source += int64(left - start)
	}
	trace.matches = append(trace.matches, PatchMatchInfo{Kind: kind, TargetStart: left, TargetEnd: right, CombinedStart: source})
}
