package windows

import (
	"bytes"
	"encoding/binary"
	"testing"
)

type testLSBWriter struct {
	data []byte
	bit  int
}

func (w *testLSBWriter) write(value uint32, count int) {
	for index := 0; index < count; index++ {
		if w.bit&7 == 0 {
			w.data = append(w.data, 0)
		}
		w.data[w.bit>>3] |= byte((value>>index)&1) << (w.bit & 7)
		w.bit++
	}
}

func literalDS(data []byte) []byte {
	var writer testLSBWriter
	for _, value := range data {
		if value&0x80 != 0 {
			writer.write(1, 2)
		} else {
			writer.write(2, 2)
		}
		writer.write(uint32(value&0x7f), 7)
	}
	writer.write(0, 8)
	return writer.data
}

func TestDecompressWin9xDS(t *testing.T) {
	want := []byte("W3\x00\x04native W4 test")
	got, err := decompressWin9xDS(literalDS(want), win9xW4ChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("decoded %q, want %q", got, want)
	}
}

func TestUnpackWin9xW4(t *testing.T) {
	want := []byte("W3\x00\x04native W4 test")
	compressed := literalDS(want)
	headerOffset := 0x40
	chunkOffset := headerOffset + 20
	input := make([]byte, chunkOffset+len(compressed))
	copy(input, "MZ")
	binary.LittleEndian.PutUint32(input[0x3c:0x40], uint32(headerOffset))
	copy(input[headerOffset:], "W4\x00\x04")
	binary.LittleEndian.PutUint16(input[headerOffset+4:headerOffset+6], win9xW4ChunkSize)
	binary.LittleEndian.PutUint16(input[headerOffset+6:headerOffset+8], 1)
	copy(input[headerOffset+8:], "DS")
	binary.LittleEndian.PutUint32(input[headerOffset+16:headerOffset+20], uint32(chunkOffset))
	copy(input[chunkOffset:], compressed)

	got, found, err := unpackWin9xW4(input)
	if err != nil {
		t.Fatal(err)
	}
	if !found || !bytes.Equal(got[headerOffset:], want) || !bytes.Equal(got[:2], []byte("MZ")) {
		t.Fatalf("unexpected unpack result: found=%t size=%d", found, len(got))
	}
}
