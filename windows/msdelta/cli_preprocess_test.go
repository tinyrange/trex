package msdelta

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestCLIMetadataBitstream(t *testing.T) {
	w := newTestBitWriter()
	w.bit(1)
	fields := []uint32{0x1000, 0x400, 0x2000, 5, 0x1080, 0x1200, 0x80, 0x1280, 0x40, 0x12c0, 0x80, 0x1340, 16, 0x1080, 0x100}
	for _, f := range fields {
		writeTestRawBits(w, uint64(f), 32)
	}
	w.bit(0)
	w.bit(1)
	w.bit(0)
	writeTestRawBits(w, 1|(1<<6), 64)
	writeTestRawBits(w, 1, 32)
	writeTestRawBits(w, 2, 32)
	w.bit(0) // absent map
	r, err := newBitReader(w.bytes())
	if err != nil {
		t.Fatal(err)
	}
	m, err := readCLIPreprocessMetadata(r)
	if err != nil {
		t.Fatal(err)
	}
	m, err = readCLIPreprocessMaps(r, m)
	if err != nil {
		t.Fatal(err)
	}
	if !r.atEnd() || m.MetadataOffset != 0x1000 || m.Streams[2].Offset != 0x12c0 || m.HeapWidths != [3]uint8{2, 4, 2} || m.Rows[6] != 2 {
		t.Fatalf("metadata: %+v", m)
	}
	l, err := layoutCLIMetadata(m)
	if err != nil {
		t.Fatal(err)
	}
	if l.rowSizes[0] != 16 || l.rowSizes[6] != 14 || l.tableOffsets[6] != 0x10b0 {
		t.Fatalf("layout: %+v", l)
	}
}

func TestCLIColumnWidths(t *testing.T) {
	m := &CLIPreprocessInfo{HeapWidths: [3]uint8{2, 2, 2}}
	if m.columnWidth(cliTypeDefOrRef) != 2 {
		t.Fatal("small coded index")
	}
	m.Rows[27] = 16384
	if m.columnWidth(cliTypeDefOrRef) != 4 || m.columnWidth(27) != 2 {
		t.Fatal("coded-index tag-bit threshold")
	}
	m.Rows[27] = 65536
	if m.columnWidth(27) != 4 {
		t.Fatal("wide table index")
	}
	m.HeapWidths[2] = 4
	if m.columnWidth(cliBlob) != 4 || m.columnWidth(cliStrings) != 2 {
		t.Fatal("independent heap widths")
	}
}

func TestCLIMetadataRejectsTruncatedTable(t *testing.T) {
	m := &CLIPreprocessInfo{MetadataPresent: true, MetadataOffset: 0x1000, MetadataSize: 28, HeapWidths: [3]uint8{2, 2, 2}, ValidTables: 1}
	m.Streams[4] = CLIStreamInfo{Offset: 0x1000, Size: 28}
	m.Rows[0] = ^uint32(0)
	if _, err := layoutCLIMetadata(m); err == nil {
		t.Fatal("accepted table outside stream")
	}
}

func makeTestCLIImage(t *testing.T) ([]byte, *cliMetadata) {
	t.Helper()
	data := makeTimestampTestPE(0x11223344)
	data = append(data, make([]byte, 0x800-len(data))...)
	const optional = 0x40 + 24
	clear(data[optional+96 : optional+96+16*8])
	put32(data, optional+96+14*8, 0x1000)
	put32(data, optional+96+14*8+4, 72)
	put32(data, optional+0xe0+16, 0x600)
	put32(data, optional+0xe0+8, 0x600)
	clear(data[0x200:])
	put32(data, 0x200, 72)
	put32(data, 0x208, 0x1080)
	put32(data, 0x20c, 0x100)
	put32(data, 0x210, 1) // ILONLY
	copy(data[0x280:], "BSJB")
	put32(data, 0x28c, 4)
	copy(data[0x290:], "v4\x00\x00")
	binary.LittleEndian.PutUint16(data[0x296:], 1)
	put32(data, 0x298, 0x30)
	put32(data, 0x29c, 42)
	copy(data[0x2a0:], "#~\x00\x00")
	data[0x2b4] = 2
	put64(data, 0x2b8, 1<<6)
	put32(data, 0x2c8, 1)
	put32(data, 0x2cc, 0x1300)
	data[0x500], data[0x501] = 6, 0x2a // tiny body containing ret
	pe, err := parsePELayout(data)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseCLIMetadata(data, pe)
	if err != nil {
		t.Fatal(err)
	}
	return data, m
}

func TestCLIIdentityMapSourceAndRVAs(t *testing.T) {
	source, m := makeTestCLIImage(t)
	if m.tableOffsets[6] != 0x2cc || m.rowSizes[6] != 14 || m.Rows[6] != 1 {
		t.Fatal("incorrect method table layout")
	}
	dst := bytes.Clone(source)
	rift := riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0x1300, target: 0x1400}}}
	if err := transformCLIMetadata(dst, source, m, &CLIPreprocessInfo{}, rift); err != nil {
		t.Fatal(err)
	}
	if get32(dst, 0x2cc) != 0x1400 || get32(source, 0x2cc) != 0x1300 {
		t.Fatal("RVA transform mutated source or missed method")
	}
	put32(dst, 0x2cc, 0x1300)
	if !bytes.Equal(dst, source) {
		t.Fatal("RVA transform changed unrelated metadata or IL")
	}
	put32(source, 0x2cc, 0)
	dst = bytes.Clone(source)
	if err := transformCLIMetadata(dst, source, m, &CLIPreprocessInfo{}, riftTable{entries: []riftEntry{{source: 0, target: 100}}}); err != nil {
		t.Fatal(err)
	}
	// A null RVA (abstract/PInvoke method) must not be made non-null.
	if get32(dst, 0x2cc) != 0 {
		t.Fatal("null RVA was transformed")
	}
}

func TestCLIParserRejectsMalformedStream(t *testing.T) {
	source, _ := makeTestCLIImage(t)
	pe, _ := parsePELayout(source)
	for _, change := range []struct {
		off   int
		value uint32
	}{{0x29c, 0xffffffff}, {0x28c, 0xffffffff}, {0x2c8, 0xffffffff}, {0x20c, 0xffffffff}} {
		data := bytes.Clone(source)
		put32(data, change.off, change.value)
		if _, err := parseCLIMetadata(data, pe); err == nil {
			t.Fatalf("accepted malformed field at %#x", change.off)
		}
	}
}

func writeTestCLIMetadata(w *testBitWriter, m *CLIPreprocessInfo) {
	w.bit(1)
	fields := []uint32{m.MetadataOffset, m.MetadataSize, m.MetadataRVA, m.StreamCount, m.StreamHeadersEnd}
	for _, s := range m.Streams {
		fields = append(fields, s.Offset, s.Size)
	}
	for _, f := range fields {
		writeTestRawBits(w, uint64(f), 32)
	}
	for _, width := range m.HeapWidths {
		w.bit(byte(width/2 - 1))
	}
	writeTestRawBits(w, m.ValidTables, 64)
	for id, n := range m.Rows {
		if m.ValidTables&(uint64(1)<<id) != 0 {
			writeTestRawBits(w, uint64(n), 32)
		}
	}
}

func TestCLIMetadataReadsPrecedingPointerNormalization(t *testing.T) {
	source, m := makeTestCLIImage(t)
	const optional = 0x40 + 24
	put16(source, 0x44, 0x14c)
	put32(source, optional+28, 0x400000)
	put32(source, optional+56, 0x100000)
	// The unaligned bytes preceding a narrow MethodDef.Name cell form
	// apparent VA 0x4b8300. RELOCS rebases it by 0x1000, changing the
	// name index from 0x4b83 to 0x4b93 before CLI's identity heap map.
	name := m.tableOffsets[6] + 8
	put16(source, name, 0x4b83)
	pp := newTestBitWriter()
	writeTestRawBits(pp, 0x401000, 64)
	writeTestRawBits(pp, 0, 32)
	writeTestRawBits(pp, 0x11223344, 32)
	pp.bit(0)
	writeTestCLIMetadata(pp, m.CLIPreprocessInfo)
	pp.bit(0)
	pp.bit(0)
	got, _, err := preparePE(source, pp.bytes(), int64(peTransformRelocs|peTransformCLI4Metadata))
	if err != nil {
		t.Fatal(err)
	}
	if value := get16(got, name); value != 0x4b93 {
		t.Fatalf("CLI overwrote prior normalization: name = %#x", value)
	}
	if get16(source, name) != 0x4b83 {
		t.Fatal("preprocessing mutated input")
	}
}

func TestLegacyMetadataCopyCoordinatesSupportWidthChanges(t *testing.T) {
	for _, heapWidth := range []uint8{2, 4} {
		t.Run(fmt.Sprint(heapWidth), func(t *testing.T) {
			source, _ := makeTestCLIImage(t)
			// Two rows exercise the upper-exclusive width-conversion walk.
			put32(source, 0x2c8, 2)
			put32(source, 0x29c, 64)
			layout, err := parsePELayout(source)
			if err != nil {
				t.Fatal(err)
			}
			target, err := parseCLIMetadata(source, layout)
			if err != nil {
				t.Fatal(err)
			}
			target.HeapWidths[0] = heapWidth
			target.MetadataOffset += 0x20
			target.StreamHeadersEnd += 0x20
			target.Streams[4].Offset += 0x20
			pp := newTestBitWriter()
			writeTestRawBits(pp, 0x10000000, 64)
			writeTestRawBits(pp, 0, 32)
			writeTestRawBits(pp, 0x55667788, 32)
			pp.bit(0)
			writeTestCLIMetadata(pp, target.CLIPreprocessInfo)
			pp.bit(0)
			pp.bit(0)
			preprocess := pp.bytes()
			_, legacy, err := preparePE(source, preprocess, int64(peTransformCLIMetadata))
			if err != nil {
				t.Fatal(err)
			}
			_, cli4, err := preparePE(source, preprocess, int64(peTransformCLI4Metadata))
			if err != nil {
				t.Fatal(err)
			}
			const coordinate = 0x2ec
			wantLegacy := int64(0x2cc)
			if got := legacy.targetToSource.mapForward(coordinate); got != wantLegacy {
				t.Fatalf("legacy copy coordinate = %#x, want %#x", got, wantLegacy)
			}
			if got := cli4.targetToSource.mapForward(coordinate); got != 0x2cc {
				t.Fatalf("CLI4 metadata copy coordinate = %#x, want %#x", got, 0x2cc)
			}
		})
	}
}

func TestLegacyCLIGenericParameterExtent(t *testing.T) {
	for _, constraints := range []uint32{0, 1} {
		for _, padding := range []uint32{0, 2} {
			t.Run(fmt.Sprintf("constraints%d_padding%d", constraints, padding), func(t *testing.T) {
				source, _ := makeTestCLIImage(t)
				put64(source, 0x2b8, 1<<6|1<<42|1<<44)
				// Modern rows occupy 58 bytes plus four per constraint. Legacy's
				// extra GenericParam.Kind needs two more, whether table44 is empty
				// or not. Only the declared table extent controls eligibility.
				put32(source, 0x29c, 58+4*constraints+padding)
				put32(source, 0x2cc, 1) // GenericParam count
				put32(source, 0x2d0, constraints)
				put32(source, 0x2d4, 0x1300) // MethodDef starts after three counts.
				layout, err := parsePELayout(source)
				if err != nil {
					t.Fatal(err)
				}
				target, err := parseCLIMetadata(source, layout)
				if err != nil {
					t.Fatal(err)
				}
				target.MetadataOffset += 0x20
				target.StreamHeadersEnd += 0x20
				target.Streams[4].Offset += 0x20
				target.Streams[4].Size = 60 + 4*constraints
				pp := newTestBitWriter()
				writeTestRawBits(pp, 0x10000000, 64)
				writeTestRawBits(pp, 0, 32)
				writeTestRawBits(pp, 0x55667788, 32)
				pp.bit(0)
				writeTestCLIMetadata(pp, target.CLIPreprocessInfo)
				pp.bit(0)
				pp.bit(0)
				preprocess := pp.bytes()
				for _, flags := range []uint64{peTransformCLIMetadata, peTransformCLI4Metadata} {
					_, prepared, err := preparePE(source, preprocess, int64(flags))
					if err != nil {
						t.Fatal(err)
					}
					const coordinate = 0x2f4
					want := int64(0x2d4)
					if padding == 0 && flags == peTransformCLIMetadata {
						want = layout.fileToRVA().reverse().mapForward(coordinate)
					}
					if got := prepared.targetToSource.mapForward(coordinate); got != want {
						t.Fatalf("flags %#x: copy = %#x, want %#x", flags, got, want)
					}
				}
			})
		}
	}
}

func TestCLISourceRVAsWithoutManagedTargetDescriptor(t *testing.T) {
	source, _ := makeTestCLIImage(t)
	pp := newTestBitWriter()
	writeTestRawBits(pp, 0x10000000, 64)
	writeTestRawBits(pp, 0, 32)
	writeTestRawBits(pp, 0x11223344, 32)
	pp.bit(0) // target RVA map
	pp.bit(0) // no managed target descriptor
	pp.bit(1) // source RVA map
	// A complete 252-symbol integer alphabet: 248 eight-bit codes and
	// four seven-bit codes. Both map coordinates use the same format.
	for range 2 {
		writeTestRawBits(pp, 0, 8)
		writeTestRawBits(pp, 0, 8)
		writeTestRawBits(pp, 248, 8)
		writeTestRawBits(pp, 7, 4)
	}
	lengths := bytes.Repeat([]byte{8}, intFormatSymbols)
	for i := 248; i < len(lengths); i++ {
		lengths[i] = 7
	}
	pp.number(1)
	writeTestHuffmanSymbol(t, pp, lengths, 0)  // source coordinate zero
	writeTestHuffmanSymbol(t, pp, lengths, 16) // displacement 256
	writeTestRawBits(pp, 0, 7)
	pp.bit(0) // no CLI remapping: metadata references remain identity
	got, _, err := preparePE(source, pp.bytes(), int64(peTransformCLIMetadata|peTransformCLIDisasm))
	if err != nil {
		t.Fatal(err)
	}
	if value := get32(got, 0x2cc); value != 0x1400 {
		t.Fatalf("source MethodDef RVA = %#x, want %#x", value, 0x1400)
	}
	if get32(source, 0x2cc) != 0x1300 {
		t.Fatal("mutated source")
	}
}

func TestManagedTargetDescriptorAllowsNativePEBasis(t *testing.T) {
	source, target := makeTestCLIImage(t)
	const directory = 0x40 + 24 + 96 + 14*8
	put32(source, directory, 0)
	put32(source, directory+4, 0)
	pp := newTestBitWriter()
	writeTestRawBits(pp, 0x10000000, 64)
	writeTestRawBits(pp, 0, 32)
	writeTestRawBits(pp, 0x55667788, 32)
	pp.bit(0)
	writeTestCLIMetadata(pp, target.CLIPreprocessInfo)
	pp.bit(0)
	pp.bit(0)
	preprocess := pp.bytes()
	if _, _, err := preparePE(source, preprocess, int64(peTransformCLIMetadata)); err != nil {
		t.Fatalf("native basis for managed target rejected: %v", err)
	}
	// Absence is distinct from a present invalid CLI directory. Do not turn
	// corrupt source metadata into a silently unnormalized native basis.
	put32(source, directory, 0xffffffff)
	put32(source, directory+4, 1)
	if _, _, err := preparePE(source, preprocess, int64(peTransformCLIMetadata)); err == nil {
		t.Fatal("malformed present source CLI directory accepted")
	}
}

func TestApplyCLIIdentityMapsVerifiesHash(t *testing.T) {
	source, m := makeTestCLIImage(t)
	// Keep file and RVA coordinates identical so the synthetic record can
	// omit both native maps while exercising real source-copy decoding.
	put32(source, 0x40+24+0xe0+12, 0x200)
	put32(source, 0x40+24+96+14*8, 0x200)
	put32(source, 0x208, 0x280)
	put32(source, 0x2cc, 0x500)
	pe, err := parsePELayout(source)
	if err != nil {
		t.Fatal(err)
	}
	m, err = parseCLIMetadata(source, pe)
	if err != nil {
		t.Fatal(err)
	}
	const targetTime = 0x55667788
	pp := newTestBitWriter()
	writeTestRawBits(pp, 0x10000000, 64)
	writeTestRawBits(pp, 0, 32)
	writeTestRawBits(pp, targetTime, 32)
	pp.bit(0)
	writeTestCLIMetadata(pp, m.CLIPreprocessInfo)
	pp.bit(0)
	pp.bit(0)
	patch := newTestBitWriter()
	patch.bit(0)
	patch.bit(1)
	for off := 0; off < len(source); off += 8 {
		writeTestHuffmanSymbol(t, patch, defaultHuffmanLengths(mainSymbols), 256+3*8+7)
	}
	want := bytes.Clone(source)
	put32(want, 0x48, targetTime)
	put32(want, 0x40+24+64, 0)
	hash := sha256.Sum256(want)
	header := newTestBitWriter()
	header.number(0xf5)
	header.number(0x10)
	header.number(peTransformCLI4Metadata)
	header.number(uint64(len(want)))
	header.number(0x800c)
	header.buffer(hash[:])
	header.buffer(pp.bytes())
	header.buffer(patch.bytes())
	delta := make([]byte, coreHeaderSize)
	copy(delta, "PA30")
	delta = append(delta, header.bytes()...)
	got, err := Apply(source, delta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("managed source-copy reconstruction differs")
	}
}

func TestCLIMapsShareIntegerFormats(t *testing.T) {
	w := newTestBitWriter()
	w.bit(1)
	for range 4 {
		writeTestRawBits(w, 0, 8)
		writeTestRawBits(w, 0, 8)
		writeTestRawBits(w, 248, 8)
		writeTestRawBits(w, 7, 4)
	}
	lengths := make([]byte, 252)
	for i := range lengths {
		lengths[i] = 8
		if i >= 248 {
			lengths[i] = 7
		}
	}
	for i := 0; i < 68; i++ {
		if i != 0 && i != 10 {
			w.number(0)
			continue
		}
		w.number(1)
		writeTestHuffmanSymbol(t, w, lengths, 3)
		writeTestHuffmanSymbol(t, w, lengths, 1)
	}
	r, err := newBitReader(w.bytes())
	if err != nil {
		t.Fatal(err)
	}
	m, err := readCLIPreprocessMaps(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !r.atEnd() || len(m.HeapMaps[0]) != 1 || len(m.TableMaps[6]) != 1 {
		t.Fatal("shared-format maps were not read")
	}
	if m.HeapMaps[0][0] != (PERiftEntry{Source: 3, Target: 4}) || m.TableMaps[6][0] != m.HeapMaps[0][0] {
		t.Fatal("incorrect cumulative map values")
	}
}

func TestCLIInstructionFlagsPreserveVerifiedSourceCopies(t *testing.T) {
	source, _ := makeTestCLIImage(t)
	// Keep the tested method before a final sentinel row: native MSDelta's
	// body enumerator does not visit the last MethodDef row.
	put32(source, 0x29c, 56) // table header plus two 14-byte MethodDef rows
	put32(source, 0x2c8, 2)
	put32(source, 0x40+24+0xe0+12, 0x200)
	put32(source, 0x40+24+96+14*8, 0x200)
	put32(source, 0x208, 0x280)
	put32(source, 0x2cc, 0x500)
	source[0x500] = 6<<2 | 2
	copy(source[0x501:], []byte{0x72, 3, 0, 0, 0x70, 0x2a})
	pe, err := parsePELayout(source)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseCLIMetadata(source, pe)
	if err != nil {
		t.Fatal(err)
	}
	pp := newTestBitWriter()
	writeTestRawBits(pp, 0x10000000, 64)
	writeTestRawBits(pp, 0, 32)
	writeTestRawBits(pp, 0x11223344, 32)
	pp.bit(0)
	writeTestCLIMetadata(pp, m.CLIPreprocessInfo)
	pp.bit(0)
	pp.bit(1)
	for range 4 {
		writeTestRawBits(pp, 0, 8)
		writeTestRawBits(pp, 0, 8)
		writeTestRawBits(pp, 248, 8)
		writeTestRawBits(pp, 7, 4)
	}
	lengths := make([]byte, 252)
	for i := range lengths {
		lengths[i] = 8
		if i >= 248 {
			lengths[i] = 7
		}
	}
	for i := range 68 {
		if i != 1 {
			pp.number(0)
			continue
		}
		pp.number(1)
		writeTestHuffmanSymbol(t, pp, lengths, 3)
		writeTestHuffmanSymbol(t, pp, lengths, 1) // US offset3 ->4
	}
	patch := newTestBitWriter()
	patch.bit(0)
	patch.bit(1)
	for off := 0; off < len(source); off += 8 {
		writeTestHuffmanSymbol(t, patch, defaultHuffmanLengths(mainSymbols), 256+3*8+7)
	}
	preprocessBytes, patchBytes := pp.bytes(), patch.bytes()
	for _, flags := range []uint64{0, peTransformCLIMetadata, peTransformCLI4Metadata, peTransformCLIDisasm, peTransformCLI4Disasm, peTransformCLI4Disasm | peTransformCLI4Metadata} {
		want := bytes.Clone(source)
		put32(want, 0x40+24+64, 0)
		if flags&(peTransformCLIDisasm|peTransformCLI4Disasm) != 0 {
			want[0x502] = 4
		}
		hash := sha256.Sum256(want)
		header := newTestBitWriter()
		header.number(0xf5)
		header.number(0x10)
		header.number(flags)
		header.number(uint64(len(want)))
		header.number(0x800c)
		header.buffer(hash[:])
		header.buffer(preprocessBytes)
		header.buffer(patchBytes)
		delta := make([]byte, coreHeaderSize)
		copy(delta, "PA30")
		delta = append(delta, header.bytes()...)
		got, err := Apply(source, delta)
		if err != nil {
			t.Fatalf("flags %#x: %v", flags, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("flags %#x: incorrect instruction normalization", flags)
		}
	}
}
