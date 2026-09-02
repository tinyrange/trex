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
