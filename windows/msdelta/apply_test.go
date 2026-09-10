package msdelta

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"testing"
)

func TestApplyLiteralPatch(t *testing.T) {
	patch := newTestBitWriter()
	patch.bit(0) // empty base rift table
	patch.bit(1) // default Huffman tables
	writeTestHuffmanSymbol(t, patch, defaultHuffmanLengths(mainSymbols), int('A'))

	targetHash := sha256.Sum256([]byte{'A'})
	outer := newTestBitWriter()
	outer.number(1) // raw files
	outer.number(1)
	outer.number(0)
	outer.number(1)
	outer.number(0x800c)
	outer.buffer(targetHash[:])
	outer.buffer(nil)
	outer.buffer(patch.bytes())
	delta := make([]byte, coreHeaderSize)
	copy(delta, "PA30")
	binary.LittleEndian.PutUint64(delta[4:], 0x01cd456789abcdef)
	delta = append(delta, outer.bytes()...)

	target, err := Apply(nil, delta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(target, []byte{'A'}) {
		t.Fatalf("target = %x", target)
	}
}

func TestApplyLZXPreservesFinalDebugTimestamp(t *testing.T) {
	const sourceTimestamp, targetTimestamp = 0x11223344, 0x55667788
	source := makeTimestampTestPE(sourceTimestamp)
	want := bytes.Clone(source)
	put32(want, 0x40+8, targetTimestamp)
	// The debug/export timestamps deliberately retain the source value.
	// Equality is not evidence that a decoded LZX field needs restoration.
	patch := newTestBitWriter()
	patch.bit(0)
	patch.bit(1)
	lengths := defaultHuffmanLengths(mainSymbols)
	for _, value := range want {
		writeTestHuffmanSymbol(t, patch, lengths, int(value))
	}
	preprocess := newTestBitWriter()
	writeTestRawBits(preprocess, 0x10000000, 64)
	writeTestRawBits(preprocess, 0, 32)
	writeTestRawBits(preprocess, targetTimestamp, 32)
	for range 4 {
		preprocess.bit(0)
	}
	targetHash := sha256.Sum256(want)
	outer := newTestBitWriter()
	outer.number(0xf)
	outer.number(2)
	outer.number(0)
	outer.number(uint64(len(want)))
	outer.number(0x800c)
	outer.buffer(targetHash[:])
	outer.buffer(preprocess.bytes())
	outer.buffer(patch.bytes())
	delta := make([]byte, coreHeaderSize)
	copy(delta, "PA30")
	delta = append(delta, outer.bytes()...)
	got, err := Apply(source, delta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("rewrote final LZX timestamps")
	}
}

func TestPreparedSourceInspectionRequiresDeclaredSourceHash(t *testing.T) {
	if _, err := InspectPreparedSourceRange([]byte("source"), testPA31(t), 0, 1); err == nil {
		t.Fatal("accepted source different from PA31 extension hash")
	}
}

func TestApplyPEPreprocessedSourceCanProduceRawTarget(t *testing.T) {
	want := []byte("<?xml version=\"1.0\"?>")
	patch := newTestBitWriter()
	patch.bit(0) // empty base rift table
	patch.bit(1) // default Huffman tables
	lengths := defaultHuffmanLengths(mainSymbols)
	for _, value := range want {
		writeTestHuffmanSymbol(t, patch, lengths, int(value))
	}

	preprocess := newTestBitWriter()
	writeTestRawBits(preprocess, 0x10000000, 64)
	writeTestRawBits(preprocess, 0, 32)
	writeTestRawBits(preprocess, 0x55667788, 32)
	preprocess.bit(0) // target RVA-to-file rift absent
	preprocess.bit(0) // managed metadata absent
	preprocess.bit(0) // source-to-target RVA rift absent
	preprocess.bit(0) // managed map absent

	targetHash := sha256.Sum256(want)
	outer := newTestBitWriter()
	outer.number(0xf5)
	outer.number(0x20)
	outer.number(peTransformUnbind)
	outer.number(uint64(len(want)))
	outer.number(0x800c)
	outer.buffer(targetHash[:])
	outer.buffer(preprocess.bytes())
	outer.buffer(patch.bytes())
	delta := make([]byte, coreHeaderSize)
	copy(delta, "PA30")
	delta = append(delta, outer.bytes()...)

	got, err := Apply(makeTestPE32(0x10000000, 0, 0x11223344), delta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("target = %q, want %q", got, want)
	}
	source := makeTestPE32(0x10000000, 0x12345678, 0x11223344)
	unchanged := bytes.Clone(source)
	layout, err := parsePELayout(source)
	if err != nil {
		t.Fatal(err)
	}
	start := int(layout.checksumOffset)
	prepared, err := InspectPreparedSourceRange(source, delta, start, start+4)
	if err != nil || !bytes.Equal(prepared, make([]byte, 4)) {
		t.Fatalf("prepared checksum = %x, %v", prepared, err)
	}
	prepared[0] = 0xff
	if !bytes.Equal(source, unchanged) {
		t.Fatal("inspection mutated source")
	}
	for _, bounds := range [][2]int{{-1, 4}, {4, 4}, {5, 4}, {0, len(source) + 1}} {
		if _, err := InspectPreparedSourceRange(source, delta, bounds[0], bounds[1]); err == nil {
			t.Fatalf("accepted invalid bounds %v", bounds)
		}
	}
}

func TestApplyLZXRestoresX86E8WithoutReplacingFinalPELayout(t *testing.T) {
	const call = 0xd0
	want := makeTestPE32(0x10000000, 0x87654321, 0x55667788)
	want[call] = 0xe8
	binary.LittleEndian.PutUint32(want[call+1:], 0x20)
	encoded := append([]byte(nil), want...)
	binary.LittleEndian.PutUint32(encoded[call+1:], uint32(call+0x20))

	patch := newTestBitWriter()
	patch.bit(0) // empty base rift table
	patch.bit(1) // default Huffman tables
	lengths := defaultHuffmanLengths(mainSymbols)
	for _, value := range encoded {
		writeTestHuffmanSymbol(t, patch, lengths, int(value))
	}

	// Zero target fields make an accidental full PE restoration observable. An
	// ordinary LZX target already carries its final structural fields.
	preprocess := newTestBitWriter()
	writeTestRawBits(preprocess, 0, 64)
	writeTestRawBits(preprocess, 0, 32)
	writeTestRawBits(preprocess, 0, 32)
	preprocess.bit(0) // target RVA-to-file rift absent
	preprocess.bit(0) // managed metadata absent
	preprocess.bit(0) // source-to-target RVA rift absent
	preprocess.bit(0) // managed map absent

	targetHash := sha256.Sum256(want)
	outer := newTestBitWriter()
	outer.number(0xf5)
	outer.number(0x20)
	outer.number(peTransformX86E8)
	outer.number(uint64(len(want)))
	outer.number(0x800c)
	outer.buffer(targetHash[:])
	outer.buffer(preprocess.bytes())
	outer.buffer(patch.bytes())
	delta := make([]byte, coreHeaderSize)
	copy(delta, "PA30")
	delta = append(delta, outer.bytes()...)

	got, err := Apply(makeTestPE32(0x20000000, 0x12345678, 0x11223344), delta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("target mismatch: got %x, want %x", sha256.Sum256(got), targetHash)
	}
}

func TestApplyBoundedRejectsDeclaredTargetBeforeDecode(t *testing.T) {
	metadata := newTestBitWriter()
	metadata.number(1) // raw files
	metadata.number(1)
	metadata.number(0)
	metadata.number(65 << 20)
	metadata.number(0)
	metadata.buffer(nil)
	metadata.buffer(nil)
	metadata.buffer(nil)
	delta := append(append([]byte("PA30"), make([]byte, 8)...), metadata.bytes()...)
	if _, err := ApplyBounded(nil, delta, 64<<20); err == nil {
		t.Fatal("ApplyBounded accepted an oversized declared target")
	}
}

func TestApplyDispatchesLZMSContainer(t *testing.T) {
	want := []byte("target")
	container := make([]byte, 24+4+len(want))
	binary.LittleEndian.PutUint32(container[0:4], 0xc0e5510a)
	binary.LittleEndian.PutUint16(container[4:6], 24)
	container[7] = 5
	binary.LittleEndian.PutUint64(container[8:16], uint64(len(want)))
	binary.LittleEndian.PutUint32(container[16:20], uint32(len(want)))
	checksum := crc32.NewIEEE()
	_, _ = checksum.Write(container[:6])
	_, _ = checksum.Write(container[7:24])
	container[6] = byte(checksum.Sum32())
	binary.LittleEndian.PutUint32(container[24:28], uint32(len(want)))
	copy(container[28:], want)

	targetHash := sha256.Sum256(want)
	outer := newTestBitWriter()
	outer.number(1)
	outer.number(1)
	outer.number(0)
	outer.number(uint64(len(want)))
	outer.number(0x800c)
	outer.buffer(targetHash[:])
	outer.buffer(nil)
	outer.buffer(container)
	delta := make([]byte, coreHeaderSize)
	copy(delta, "PA30")
	delta = append(delta, outer.bytes()...)

	got, err := Apply(nil, delta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("target = %q", got)
	}
	inspection, err := InspectPatchRangeBytesBounded(nil, delta, 1, 4, uint64(len(want)))
	if err != nil || !bytes.Equal(inspection.Decoded, want[1:4]) || len(inspection.Matches) != 0 || len(inspection.PETransforms) != 0 {
		t.Fatalf("byte-only inspection = %#v, %v", inspection, err)
	}
	if _, err := InspectPatchRangeBytesBounded(nil, delta, 0, len(want), uint64(len(want)-1)); err == nil {
		t.Fatal("LZMS inspection ignored target size bound")
	}
	if _, err := InspectPatchRangeBounded(nil, delta, 0, len(want), uint64(len(want))); err == nil {
		t.Fatal("LZMS inspection claimed unsupported match provenance")
	}
}

func TestApplyDispatchesLZMSBinaryDelta(t *testing.T) {
	want := []byte("target")
	inner := appendBSDiffTestBlock(nil, 0, int64(len(want)), 8, nil, want)
	container := make([]byte, 24+4+len(inner))
	binary.LittleEndian.PutUint32(container[0:4], 0xc0e5510a)
	binary.LittleEndian.PutUint16(container[4:6], 24)
	container[7] = 5
	binary.LittleEndian.PutUint64(container[8:16], uint64(len(inner)))
	binary.LittleEndian.PutUint32(container[16:20], uint32(len(inner)))
	checksum := crc32.NewIEEE()
	_, _ = checksum.Write(container[:6])
	_, _ = checksum.Write(container[7:24])
	container[6] = byte(checksum.Sum32())
	binary.LittleEndian.PutUint32(container[24:28], uint32(len(inner)))
	copy(container[28:], inner)

	targetHash := sha256.Sum256(want)
	outer := newTestBitWriter()
	outer.number(1)
	outer.number(1)
	outer.number(0)
	outer.number(uint64(len(want)))
	outer.number(0x800c)
	outer.buffer(targetHash[:])
	outer.buffer(nil)
	outer.buffer(container)
	delta := make([]byte, coreHeaderSize)
	copy(delta, "PA30")
	delta = append(delta, outer.bytes()...)

	got, err := Apply([]byte("unused"), delta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("target = %q", got)
	}
	inspection, err := InspectPatchRangeBytesBounded([]byte("unused"), delta, 1, 4, 64)
	if err != nil || !bytes.Equal(inspection.Decoded, want[1:4]) || len(inspection.Matches) != 0 {
		t.Fatalf("nested byte-only inspection = %#v, %v", inspection, err)
	}
}

func TestApplyLZMSBinaryDeltaUsesPreparedPESourceAndFullRestore(t *testing.T) {
	const (
		sourceTimestamp = 0x11223344
		targetTimestamp = 0x55667788
		imageBase       = 0x10000000
	)
	source := makeTestPE32(imageBase, 0x87654321, sourceTimestamp)
	source = append(source, make([]byte, 0x500-len(source))...)
	peOffset := 0x40
	optional := peOffset + 24
	binary.LittleEndian.PutUint16(source[peOffset+6:], 1)
	binary.LittleEndian.PutUint16(source[peOffset+20:], 0xe0)
	binary.LittleEndian.PutUint32(source[optional+60:], 0x200)
	binary.LittleEndian.PutUint32(source[optional+92:], 16)
	binary.LittleEndian.PutUint32(source[optional+96+8:], 0x1000)
	binary.LittleEndian.PutUint32(source[optional+96+12:], 40)
	section := optional + 0xe0
	copy(source[section:], ".idata")
	binary.LittleEndian.PutUint32(source[section+8:], 0x200)
	binary.LittleEndian.PutUint32(source[section+12:], 0x1000)
	binary.LittleEndian.PutUint32(source[section+16:], 0x200)
	binary.LittleEndian.PutUint32(source[section+20:], 0x200)
	binary.LittleEndian.PutUint32(source[section+36:], 0x40000040)
	// One bound import descriptor. PE unbinding clears its timestamp/forwarder,
	// restores the IAT from the original thunk table, and marks .idata writable.
	binary.LittleEndian.PutUint32(source[0x200:], 0x1040)
	binary.LittleEndian.PutUint32(source[0x204:], 1)
	binary.LittleEndian.PutUint32(source[0x208:], 2)
	binary.LittleEndian.PutUint32(source[0x20c:], 0x1080)
	binary.LittleEndian.PutUint32(source[0x210:], 0x1060)
	binary.LittleEndian.PutUint32(source[0x240:], 0x1090)
	binary.LittleEndian.PutUint32(source[0x260:], imageBase+0x1234)

	preprocess := newTestBitWriter()
	writeTestRawBits(preprocess, imageBase, 64)
	writeTestRawBits(preprocess, 0, 32)
	writeTestRawBits(preprocess, targetTimestamp, 32)
	preprocess.bit(0) // target RVA-to-file rift absent
	preprocess.bit(0) // managed metadata absent
	preprocess.bit(0) // source-to-target RVA rift absent
	preprocess.bit(0) // managed map absent
	preprocessBytes := preprocess.bytes()

	prepared, restore, err := preparePE(source, preprocessBytes, int64(peTransformUnbind))
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), prepared...)
	if err := restore.restore(want); err != nil {
		t.Fatal(err)
	}
	inner := appendBSDiffTestBlock(nil, int64(len(want)), 0, 0, make([]byte, len(want)), nil)
	container := make([]byte, 24+4+len(inner))
	binary.LittleEndian.PutUint32(container[0:4], 0xc0e5510a)
	binary.LittleEndian.PutUint16(container[4:6], 24)
	container[7] = 5
	binary.LittleEndian.PutUint64(container[8:16], uint64(len(inner)))
	binary.LittleEndian.PutUint32(container[16:20], uint32(len(inner)))
	checksum := crc32.NewIEEE()
	_, _ = checksum.Write(container[:6])
	_, _ = checksum.Write(container[7:24])
	container[6] = byte(checksum.Sum32())
	binary.LittleEndian.PutUint32(container[24:28], uint32(len(inner)))
	copy(container[28:], inner)

	targetHash := sha256.Sum256(want)
	outer := newTestBitWriter()
	outer.number(0xf5)
	outer.number(0x20)
	outer.number(peTransformUnbind)
	outer.number(uint64(len(want)))
	outer.number(0x800c)
	outer.buffer(targetHash[:])
	outer.buffer(preprocessBytes)
	outer.buffer(container)
	delta := make([]byte, coreHeaderSize)
	copy(delta, "PA30")
	delta = append(delta, outer.bytes()...)

	got, err := Apply(source, delta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("nested LZMS delta did not use the prepared PE source and normal restoration")
	}
}

func TestApplyFixesPELZMSContainerTimestamp(t *testing.T) {
	const sourceTimestamp = 0x11223344
	intermediate := makeTestPE32(0x10000000, 0x87654321, sourceTimestamp)
	want := append([]byte(nil), intermediate...)
	binary.LittleEndian.PutUint32(want[0x40+8:], 0x55667788)

	container := make([]byte, 24+4+len(intermediate))
	binary.LittleEndian.PutUint32(container[0:4], 0xc0e5510a)
	binary.LittleEndian.PutUint16(container[4:6], 24)
	container[7] = 5
	binary.LittleEndian.PutUint64(container[8:16], uint64(len(intermediate)))
	binary.LittleEndian.PutUint32(container[16:20], uint32(len(intermediate)))
	checksum := crc32.NewIEEE()
	_, _ = checksum.Write(container[:6])
	_, _ = checksum.Write(container[7:24])
	container[6] = byte(checksum.Sum32())
	binary.LittleEndian.PutUint32(container[24:28], uint32(len(intermediate)))
	copy(container[28:], intermediate)

	preprocess := newTestBitWriter()
	writeTestRawBits(preprocess, 0x18000000, 64)
	writeTestRawBits(preprocess, 0x12345678, 32)
	writeTestRawBits(preprocess, 0x55667788, 32)
	preprocess.bit(0) // target RVA-to-file rift absent
	preprocess.bit(0) // managed metadata absent
	preprocess.bit(0) // source-to-target RVA rift absent
	preprocess.bit(0) // managed map absent

	targetHash := sha256.Sum256(want)
	outer := newTestBitWriter()
	outer.number(0xf5)
	outer.number(0x20)
	outer.number(0)
	outer.number(uint64(len(want)))
	outer.number(0x800c)
	outer.buffer(targetHash[:])
	outer.buffer(preprocess.bytes())
	outer.buffer(container)
	delta := make([]byte, coreHeaderSize)
	copy(delta, "PA30")
	delta = append(delta, outer.bytes()...)

	got, err := Apply(makeTestPE32(0x10000000, 0, sourceTimestamp), delta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("target timestamp was not fixed without changing final structural fields")
	}
}

func makeTestPE32(imageBase, checksum, timestamp uint32) []byte {
	data := make([]byte, 0x100)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], 0x40)
	copy(data[0x40:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(data[0x40+4:], 0x14c)
	binary.LittleEndian.PutUint32(data[0x40+8:], timestamp)
	binary.LittleEndian.PutUint16(data[0x40+20:], 96)
	optional := 0x40 + 24
	binary.LittleEndian.PutUint16(data[optional:], 0x10b)
	binary.LittleEndian.PutUint32(data[optional+28:], imageBase)
	binary.LittleEndian.PutUint32(data[optional+36:], 0x200)
	binary.LittleEndian.PutUint32(data[optional+56:], 0x1000)
	binary.LittleEndian.PutUint32(data[optional+60:], 0x200)
	binary.LittleEndian.PutUint32(data[optional+64:], checksum)
	return data
}

func writeTestRawBits(bits *testBitWriter, value uint64, count uint) {
	for bit := range count {
		bits.bit(byte(value >> bit))
	}
}

func TestApplyRejectsPreprocessing(t *testing.T) {
	metadata := newTestBitWriter()
	for _, value := range []uint64{1, 1, 0, 0, 0} {
		metadata.number(value)
	}
	metadata.buffer(nil)
	metadata.buffer([]byte{1})
	metadata.buffer([]byte{1})
	delta := append(append([]byte("PA30"), make([]byte, 8)...), metadata.bytes()...)
	if _, err := Apply(nil, delta); err == nil {
		t.Fatal("Apply accepted an unsupported preprocessing stream")
	}
}

func TestDecodePatchFullSource(t *testing.T) {
	patch := newTestBitWriter()
	patch.bit(0) // empty base rift table
	patch.bit(1) // default Huffman tables
	writeTestHuffmanSymbol(t, patch, defaultHuffmanLengths(mainSymbols), 256+3*8+1)
	target, err := decodePatch([]byte("AB"), patch.bytes(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(target, []byte("AB")) {
		t.Fatalf("target = %q", target)
	}
}

func TestDecodePatchFullSourceCrossesSourceBoundary(t *testing.T) {
	patch := newTestBitWriter()
	patch.bit(0)                                                                    // empty base rift table
	patch.bit(1)                                                                    // default Huffman tables
	writeTestHuffmanSymbol(t, patch, defaultHuffmanLengths(mainSymbols), 256+3*8+5) // source copy, length 6
	target, err := decodePatch([]byte("AB"), patch.bytes(), 6)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(target, []byte("ABABAB")) {
		t.Fatalf("target = %q", target)
	}
}

func TestDecodePatchFullSourceReanchorsAtBaseRiftBoundary(t *testing.T) {
	patch := newTestBitWriter()
	patch.bit(1) // default Huffman tables; the base rift is supplied directly
	lengths := defaultHuffmanLengths(mainSymbols)
	writeTestHuffmanSymbol(t, patch, lengths, int('X'))
	writeTestHuffmanSymbol(t, patch, lengths, 256+3*8+1) // source copy, length 2
	bits, err := newBitReader(patch.bytes())
	if err != nil {
		t.Fatal(err)
	}
	trace := &patchTraceCollector{start: 2, end: 3}
	target, err := decodePatchBodyTraced([]byte("ABCD"), bits, 3, nil, riftTable{entries: []riftEntry{
		{source: 5, target: 2}, // target offset 1 copies from source offset 2
		{source: 6, target: 0}, // target offset 2 re-anchors to source offset 0
	}}, trace)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(target, []byte("XCA")) {
		t.Fatalf("target = %q", target)
	}
	if len(trace.matches) != 1 || trace.matches[0].CombinedStart != 0 || trace.matches[0].TargetStart != 2 || trace.matches[0].TargetEnd != 3 {
		t.Fatalf("full-source trace = %#v", trace.matches)
	}
}

func TestDecodePatchExplicitSourceKeepsDistanceAcrossRiftBoundary(t *testing.T) {
	patch := newTestBitWriter()
	patch.bit(1) // default Huffman tables; the base rift is supplied directly
	lengths := defaultHuffmanLengths(mainSymbols)
	writeTestHuffmanSymbol(t, patch, lengths, int('X'))
	writeTestHuffmanSymbol(t, patch, lengths, 256+1) // slot 0, length 2
	for bit := range uint(14) {
		patch.bit(byte(uint32(0x2000) >> bit)) // signed source delta 0
	}
	bits, err := newBitReader(patch.bytes())
	if err != nil {
		t.Fatal(err)
	}
	target, err := decodePatchBody([]byte("ABCD"), bits, 3, nil, riftTable{entries: []riftEntry{
		{source: 5, target: 2}, // explicit match begins at source offset 2
		{source: 6, target: 0}, // must not re-anchor this fixed-distance match
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(target, []byte("XCD")) {
		t.Fatalf("target = %q", target)
	}
}

func TestDecodePatchTraceReportsOnlyOverlappingMatch(t *testing.T) {
	patch := newTestBitWriter()
	patch.bit(1) // default Huffman tables; the base rift is supplied directly
	lengths := defaultHuffmanLengths(mainSymbols)
	writeTestHuffmanSymbol(t, patch, lengths, int('X'))
	writeTestHuffmanSymbol(t, patch, lengths, 256+1) // slot 0, length 2
	for bit := range uint(14) {
		patch.bit(byte(uint32(0x2000) >> bit))
	}
	bits, err := newBitReader(patch.bytes())
	if err != nil {
		t.Fatal(err)
	}
	trace := &patchTraceCollector{start: 2, end: 3}
	_, err = decodePatchBodyTraced([]byte("ABCD"), bits, 3, nil, riftTable{entries: []riftEntry{
		{source: 5, target: 2},
		{source: 6, target: 0},
	}}, trace)
	if err != nil {
		t.Fatal(err)
	}
	if len(trace.matches) != 1 {
		t.Fatalf("trace matches = %#v", trace.matches)
	}
	match := trace.matches[0]
	if match.Kind != "source" || match.TargetStart != 2 || match.TargetEnd != 3 || match.CombinedStart != 3 || match.Distance != 3 {
		t.Fatalf("trace match = %#v", match)
	}
}

func TestDecodePatchSourceCopyUpdatesLRU(t *testing.T) {
	patch := newTestBitWriter()
	patch.bit(0) // empty base rift table
	patch.bit(1) // default Huffman tables
	lengths := defaultHuffmanLengths(mainSymbols)
	writeTestHuffmanSymbol(t, patch, lengths, 256+3*8+1) // source copy, length 2
	writeTestHuffmanSymbol(t, patch, lengths, 256+4*8+1) // LRU[0], length 2
	target, err := decodePatch([]byte("AB"), patch.bytes(), 4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(target, []byte("ABAB")) {
		t.Fatalf("target = %q", target)
	}
}

func TestDecodePatchDestinationCanReferenceSource(t *testing.T) {
	patch := newTestBitWriter()
	patch.bit(0) // empty base rift table
	patch.bit(1) // default Huffman tables
	writeTestHuffmanSymbol(t, patch, defaultHuffmanLengths(mainSymbols), 256+9*8+1)
	target, err := decodePatch([]byte("AB"), patch.bytes(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(target, []byte("AB")) {
		t.Fatalf("target = %q", target)
	}
}

func TestCodeSetAllowsUnusedEmptyAuxiliaryTrees(t *testing.T) {
	lengths := make([]byte, allCodeLengths)
	copy(lengths, defaultHuffmanLengths(mainSymbols))
	set, err := makeCodeSet(0, lengths)
	if err != nil {
		t.Fatal(err)
	}
	if set.main == nil || set.length != nil || set.aligned != nil {
		t.Fatalf("set = %#v", set)
	}
}

func TestHuffmanAllowsUnusedCodeSpace(t *testing.T) {
	tree, err := newHuffman([]byte{1, 0, 0}, 2)
	if err != nil {
		t.Fatal(err)
	}
	bits, err := newBitReader([]byte{0})
	if err != nil {
		t.Fatal(err)
	}
	if symbol, err := tree.decode(bits); err != nil || symbol != 0 {
		t.Fatalf("symbol = %d, error = %v", symbol, err)
	}
}

func TestApplyCreateDeltaRawSwap(t *testing.T) {
	delta, err := hex.DecodeString("504133300000000000000000182320000432000a021d5ddd1550ae83cb1aa8006dbca2e02344d325985685c62c4511a7750b8ef933011db6c307ed19efb47abc7700407c02")
	if err != nil {
		t.Fatal(err)
	}
	source := make([]byte, 0, 16*256)
	for value := byte(1); value <= 16; value++ {
		source = append(source, bytes.Repeat([]byte{value}, 256)...)
	}
	want := append([]byte(nil), source...)
	copy(want[256:512], source[512:768])
	copy(want[512:768], source[256:512])
	got, err := Apply(source, delta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("target mismatch: got %x, want %x", sha256.Sum256(got), sha256.Sum256(want))
	}
}

func writeTestHuffmanSymbol(t *testing.T, bits *testBitWriter, lengths []byte, symbol int) {
	t.Helper()
	tree, err := newHuffman(lengths, 16)
	if err != nil {
		t.Fatal(err)
	}
	for length := range tree.first {
		for code := tree.first[length]; code < 1<<uint(length+1); code++ {
			index := int(code) + tree.offset[length]
			if index < 0 || index >= len(tree.symbols) || tree.symbols[index] != symbol {
				continue
			}
			for shift := length; shift >= 0; shift-- {
				bits.bit(byte(code >> uint(shift)))
			}
			return
		}
	}
	t.Fatalf("no Huffman code for symbol %d", symbol)
}
