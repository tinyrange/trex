package lznt1

import (
	"bytes"
	"testing"
)

func TestDecodeCompressedPhrase(t *testing.T) {
	// Three literals followed by a six-byte overlapping phrase.
	encoded := []byte{0x05, 0xb0, 0x08, 'A', 'B', 'C', 0x03, 0x20}
	got, err := Decode(encoded, 9)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ABCABCABC" {
		t.Fatalf("decoded %q", got)
	}
}

func TestDecodeUncompressedChunks(t *testing.T) {
	first := bytes.Repeat([]byte{'a'}, chunkSize)
	second := []byte("tail")
	encoded := append([]byte{0xff, 0x3f}, first...)
	encoded = append(encoded, 0x03, 0x30)
	encoded = append(encoded, second...)
	got, err := Decode(encoded, len(first)+len(second))
	if err != nil {
		t.Fatal(err)
	}
	want := append(first, second...)
	if !bytes.Equal(got, want) {
		t.Fatal("uncompressed chunks differ")
	}
}

func TestDecodeComposesShortCompressedChunk(t *testing.T) {
	// Chunks are independent and may produce fewer than 4096 bytes. The next
	// chunk continues the output rather than filling the preceding chunk.
	encoded := []byte{
		0x01, 0xb0, 0x00, 'a',
		0x03, 0x30, 't', 'a', 'i', 'l',
	}
	got, err := Decode(encoded, 5)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "atail" {
		t.Fatalf("decoded %q", got)
	}
}

func TestDecodeRejectsTruncatedFinalPhrase(t *testing.T) {
	_, err := Decode([]byte{0x01, 0xb0, 0x01, 0x00}, 3)
	if err == nil {
		t.Fatal("expected truncated phrase error")
	}
}

func TestDecodeLogicalEndInsideFinalChunk(t *testing.T) {
	encoded := []byte{0x03, 0xb0, 0x00, 'a', 'b', 'c'}
	got, err := Decode(encoded, 2)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ab" {
		t.Fatalf("decoded %q", got)
	}
}

func TestDecodeRejectsInvalidDisplacement(t *testing.T) {
	_, err := Decode([]byte{0x02, 0xb0, 0x01, 0x00, 0x00}, 3)
	if err == nil {
		t.Fatal("expected invalid displacement")
	}
}

func TestDecodePhraseSplitAtPowerOfTwoBoundary(t *testing.T) {
	// At output position 16 the previous byte's zero-based position is 15,
	// so the token still has a 12-bit length and 4-bit displacement split.
	encoded := []byte{
		0x00, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
		0x00, 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
		0x01, 0x00, 0x10, // length 3, displacement 2
	}
	chunk, err := decodeChunk(encoded, 19)
	if err != nil {
		t.Fatal(err)
	}
	if string(chunk) != "abcdefghijklmnopopo" {
		t.Fatalf("decoded %q", chunk)
	}
}

func TestDecodeIgnoresUnusedFinalFlagBits(t *testing.T) {
	// MS-XCA section 3.3 publishes this 59-byte LZNT1 stream and states
	// that the unused bits in its final flag byte are ignored.
	encoded := []byte{
		0x38, 0xb0, 0x88, 0x46, 0x23, 0x20, 0x00, 0x20,
		0x47, 0x20, 0x41, 0x00, 0x10, 0xa2, 0x47, 0x01,
		0xa0, 0x45, 0x20, 0x44, 0x00, 0x08, 0x45, 0x01,
		0x50, 0x79, 0x00, 0xc0, 0x45, 0x20, 0x05, 0x24,
		0x13, 0x88, 0x05, 0xb4, 0x02, 0x4a, 0x44, 0xef,
		0x03, 0x58, 0x02, 0x8c, 0x09, 0x16, 0x01, 0x48,
		0x45, 0x00, 0xbe, 0x00, 0x9e, 0x00, 0x04, 0x01,
		0x18, 0x90, 0x00,
	}
	got, err := Decode(encoded, 142)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 142 || got[len(got)-1] != 0 {
		t.Fatalf("decoded invalid public vector: length %d, last byte %#x", len(got), got[len(got)-1])
	}
}
