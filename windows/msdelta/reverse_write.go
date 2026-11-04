package msdelta

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math/bits"
)

// CreateReversePSFRecord creates a source-bound PA31 playback record. Source is
// the installed/new content; target is the exact earlier basis to recover.
// Unlike forward PE normalization, playback copies and literals address raw
// file bytes. No executable transformation or external codec is invoked.
// maximum bounds each input and the encoded result, and cannot exceed 128 MiB.
// The caller must bind target to its admitted forward edge, not a filename or
// a reference image. File time is explicit; this function does not read a clock.
func CreateReversePSFRecord(source, target []byte, targetFileTime, maximum uint64) ([]byte, error) {
	if maximum == 0 || maximum > 128<<20 || uint64(len(source)) > maximum || uint64(len(target)) > maximum {
		return nil, fmt.Errorf("msdelta: reverse input exceeds bound")
	}
	// Same-coordinate runs are sufficient for correctness and bound matching
	// work linearly. Short matches remain literals. A bounded number of spans
	// prevents adversarial alternating data from growing the rift workspace.
	const minCopy = 16
	const maxSpans = 1 << 16
	var copies, literals []riftEntry
	var lengths []int64
	literalStart := 0
	for i := 0; i < min(len(source), len(target)); {
		if source[i] != target[i] {
			i++
			continue
		}
		start := i
		for i < min(len(source), len(target)) && source[i] == target[i] {
			i++
		}
		if i-start < minCopy {
			continue
		}
		if start > literalStart {
			literals = append(literals, riftEntry{int64(literalStart), int64(start - literalStart)})
		}
		copies = append(copies, riftEntry{int64(start), int64(start)})
		lengths = append(lengths, int64(i-start))
		literalStart = i
		if len(copies) >= maxSpans {
			break
		}
	}
	if literalStart < len(target) {
		literals = append(literals, riftEntry{int64(literalStart), int64(len(target) - literalStart)})
	}
	playback := newDeltaWriter()
	playback.raw(0x4d535250, 32)
	playback.raw(1, 32)
	if len(copies) != 0 {
		record := newDeltaWriter()
		record.raw(0, 32)
		record.raw(1, 32)
		record.rift(copies)
		for _, length := range lengths {
			record.integer(length)
		}
		playback.buffer(record.finish())
	}
	if len(literals) != 0 {
		record := newDeltaWriter()
		record.raw(1, 32)
		record.raw(1, 32)
		record.raw(0, 32) // uncompressed literals; compression is not required
		record.rift(literals)
		literalSize := 0
		for _, span := range literals {
			literalSize += int(span.target)
		}
		record.number(uint64(literalSize))
		record.align()
		for _, span := range literals {
			record.data = append(record.data, target[span.source:span.source+span.target]...)
		}
		playback.buffer(record.finish())
	}
	sourceHash, targetHash := sha256.Sum256(source), sha256.Sum256(target)
	metadata := newDeltaWriter()
	metadata.number(0x101) // RAW plus reverse playback
	metadata.number(1)     // RAW, independent of the bytes' executable architecture
	metadata.number(0)     // no forward PE transform flags
	metadata.number(uint64(len(target)))
	metadata.number(0x800c) // CALG_SHA_256
	metadata.buffer(targetHash[:])
	for _, field := range []uint64{136, 1, 0} {
		metadata.number(field)
	}
	metadata.buffer(sourceHash[:])
	outer := newDeltaWriter()
	outer.buffer(metadata.finish())
	outer.buffer(playback.finish()) // reverse playback has no preprocess buffer
	record := make([]byte, 4+coreHeaderSize)
	copy(record[4:], "PA31")
	binary.LittleEndian.PutUint64(record[8:], targetFileTime)
	record = append(record, outer.finish()...)
	if uint64(len(record)) > maximum {
		return nil, fmt.Errorf("msdelta: reverse record exceeds bound")
	}
	binary.LittleEndian.PutUint32(record, crc32.ChecksumIEEE(record[4:]))
	return record, nil
}

// deltaWriter encodes the existing LSB-first number/buffer format. The initial
// three bits contain final-byte padding, not buffer-alignment padding.
type deltaWriter struct {
	data []byte
	used uint
}

func newDeltaWriter() *deltaWriter { return &deltaWriter{data: []byte{0}, used: 3} }
func (w *deltaWriter) raw(v uint64, n uint) {
	for ; n > 0; n-- {
		if w.used == 0 {
			w.data = append(w.data, 0)
		}
		w.data[len(w.data)-1] |= byte(v&1) << w.used
		w.used = (w.used + 1) & 7
		v >>= 1
	}
}
func (w *deltaWriter) number(v uint64) {
	nibbles := max(1, (bits.Len64(v)+3)/4)
	w.raw(0, uint(nibbles-1))
	w.raw(1, 1)
	w.raw(v, uint(nibbles*4))
}
func (w *deltaWriter) align() {
	if w.used != 0 {
		w.raw(0, 8-w.used)
	}
}
func (w *deltaWriter) buffer(data []byte) {
	w.number(uint64(len(data)))
	w.align()
	w.data = append(w.data, data...)
}
func (w *deltaWriter) finish() []byte {
	pad := (8 - w.used) & 7
	w.data[0] = w.data[0]&^7 | byte(pad)
	return w.data
}
func (w *deltaWriter) integer(value int64) {
	v := uint64(value)
	negative := value < 0
	if negative {
		v = uint64(^value)
	}
	symbol, extra := int(v), uint(0)
	if v > 3 {
		extra = uint(bits.Len64(v) - 2)
		symbol = int(v>>extra) - 2 + 2*int(extra+1)
	}
	if negative {
		symbol += intFormatHalf
	}
	// The default integer tree has four 7-bit codes (124..127), then
	// 248 8-bit codes (0..247), emitted most-significant code bit first.
	code, width := uint64(symbol-4), uint(8)
	if symbol < 4 {
		code, width = uint64(124+symbol), 7
	}
	for n := width; n > 0; n-- {
		w.raw(code>>(n-1), 1)
	}
	w.raw(v, extra)
}
func (w *deltaWriter) rift(entries []riftEntry) {
	if len(entries) == 0 {
		w.raw(0, 1)
		return
	}
	w.raw(1, 1)
	for range 2 {
		w.raw(4, 8)
		w.raw(0, 8)
		w.raw(0, 8)
		for range 4 {
			w.raw(6, 4)
		} // explicit first four lengths = 7
		w.raw(8, 4) // implicit lengths = (8+1)-1 = 8
	}
	w.number(uint64(len(entries)))
	var previous, displacement int64
	for _, entry := range entries {
		w.integer(entry.source - previous)
		next := entry.target - entry.source
		w.integer(next - displacement)
		previous, displacement = entry.source, next
	}
}
