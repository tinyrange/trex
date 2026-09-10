package msdelta

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

func TestParseHeader(t *testing.T) {
	outer := newTestBitWriter()
	outer.number(15)
	outer.number(1)
	outer.number(0x20000)
	outer.number(12345)
	outer.number(0x800c)
	outer.buffer(bytes.Repeat([]byte{0xa5}, 32))
	outer.number(7)
	outer.number(8)
	outer.number(9)
	outer.buffer(bytes.Repeat([]byte{0x5a}, 32))
	metadata := outer.bytes()
	outer = newTestBitWriter()
	outer.buffer(metadata)
	outer.buffer(nil)
	outer.buffer([]byte{1, 2, 3})

	data := make([]byte, coreHeaderSize)
	copy(data, "PA31")
	binary.LittleEndian.PutUint64(data[4:], 0x01cd456789abcdef)
	data = append(data, outer.bytes()...)
	header, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if header.Version != "PA31" || header.FileTypeSet != 15 || header.FileType != 1 ||
		header.Flags != 0x20000 || header.TargetSize != 12345 || header.HashAlgorithm != 0x800c ||
		header.TargetFileTime != 0x01cd456789abcdef {
		t.Fatalf("unexpected header: %+v", header)
	}
	if !bytes.Equal(header.TargetHash, bytes.Repeat([]byte{0xa5}, 32)) {
		t.Fatalf("target hash = %x", header.TargetHash)
	}
	if len(header.Preprocess) != 0 || !bytes.Equal(header.Patch, []byte{1, 2, 3}) {
		t.Fatalf("preprocess = %x, patch = %x", header.Preprocess, header.Patch)
	}
	if header.Extension != [3]uint32{7, 8, 9} || !bytes.Equal(header.ExtensionHash, bytes.Repeat([]byte{0x5a}, 32)) {
		t.Fatalf("extension = %v, hash = %x", header.Extension, header.ExtensionHash)
	}
}

func TestParsePSFRecord(t *testing.T) {
	delta := testPA31(t)
	record := make([]byte, 4, len(delta)+4)
	binary.LittleEndian.PutUint32(record, crc32.ChecksumIEEE(delta))
	record = append(record, delta...)
	header, err := ParsePSFRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if header.Version != "PA31" || header.TargetSize != 12345 {
		t.Fatalf("unexpected header: %+v", header)
	}
	record[len(record)-1] ^= 1
	if _, err := ParsePSFRecord(record); err == nil {
		t.Fatal("ParsePSFRecord accepted a bad checksum")
	}
	if _, err := ParsePSFRecord(record[:3]); err == nil {
		t.Fatal("ParsePSFRecord accepted a truncated record")
	}
}

func TestApplyPSFRecordBoundedRejectsBadChecksumBeforeDelta(t *testing.T) {
	record := []byte{0, 0, 0, 0, 'P', 'A', '3', '0'}
	if _, err := ApplyPSFRecordBounded(nil, record, 1024); err == nil {
		t.Fatal("ApplyPSFRecordBounded accepted a bad PSF checksum")
	}
}

func testPA31(t *testing.T) []byte {
	t.Helper()
	metadataBits := newTestBitWriter()
	metadataBits.number(15)
	metadataBits.number(1)
	metadataBits.number(0x20000)
	metadataBits.number(12345)
	metadataBits.number(0x800c)
	metadataBits.buffer(bytes.Repeat([]byte{0xa5}, 32))
	metadataBits.number(7)
	metadataBits.number(8)
	metadataBits.number(9)
	metadataBits.buffer(bytes.Repeat([]byte{0x5a}, 32))
	outer := newTestBitWriter()
	outer.buffer(metadataBits.bytes())
	outer.buffer(nil)
	outer.buffer([]byte{1, 2, 3})
	data := make([]byte, coreHeaderSize)
	copy(data, "PA31")
	binary.LittleEndian.PutUint64(data[4:], 0x01cd456789abcdef)
	return append(data, outer.bytes()...)
}

func TestParseRejectsTruncatedBuffer(t *testing.T) {
	outer := newTestBitWriter()
	for range 6 {
		outer.number(0)
	}
	outer.number(4)
	data := append(append([]byte("PA30"), make([]byte, 8)...), outer.bytes()...)
	if _, err := Parse(data); err == nil {
		t.Fatal("Parse accepted a truncated buffer")
	}
}

type testBitWriter struct {
	bits []byte
}

func TestBitReaderWideUnaligned(t *testing.T) {
	for prefix := uint(0); prefix < 8; prefix++ {
		for width := uint(57); width <= 64; width++ {
			w := newTestBitWriter()
			writeTestRawBits(w, 0, prefix)
			want := uint64(0xfedcba9876543210) >> (64 - width)
			writeTestRawBits(w, want, width)
			r, err := newBitReader(w.bytes())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.read(prefix); err != nil {
				t.Fatal(err)
			}
			got, err := r.read(width)
			if err != nil || got != want || !r.atEnd() {
				t.Fatalf("prefix=%d width=%d: got %#x, want %#x: %v", prefix, width, got, want, err)
			}
		}
	}
}

func newTestBitWriter() *testBitWriter {
	return &testBitWriter{bits: []byte{0, 0, 0}}
}

func (w *testBitWriter) bit(value byte) {
	w.bits = append(w.bits, value&1)
}

func (w *testBitWriter) number(value uint64) {
	nibbles := uint(1)
	for value >= uint64(1)<<(nibbles*4) {
		nibbles++
	}
	for range nibbles - 1 {
		w.bit(0)
	}
	w.bit(1)
	for bit := uint(0); bit < nibbles*4; bit++ {
		w.bit(byte(value >> bit))
	}
}

func (w *testBitWriter) buffer(data []byte) {
	w.number(uint64(len(data)))
	for len(w.bits)%8 != 0 {
		w.bit(0)
	}
	for _, value := range data {
		for bit := uint(0); bit < 8; bit++ {
			w.bit(value >> bit)
		}
	}
}

func (w *testBitWriter) bytes() []byte {
	pad := (8 - len(w.bits)%8) % 8
	for range pad {
		w.bit(0)
	}
	w.bits[0] = byte(pad & 1)
	w.bits[1] = byte((pad >> 1) & 1)
	w.bits[2] = byte((pad >> 2) & 1)
	out := make([]byte, len(w.bits)/8)
	for index, bit := range w.bits {
		out[index/8] |= bit << (index % 8)
	}
	return out
}
