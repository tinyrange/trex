package lzms

import (
	"encoding/binary"
	"slices"
	"testing"
)

func backwardFixture(word uint16) *backwardBitReader {
	data := make([]byte, 2)
	binary.LittleEndian.PutUint16(data, word)
	reader, err := newBackwardBitReader(data)
	if err != nil {
		panic(err)
	}
	return reader
}

func TestEqualFrequencyHuffmanCodes(t *testing.T) {
	frequencies := make([]uint64, 256)
	for index := range frequencies {
		frequencies[index] = 1
	}
	code, err := buildHuffmanCode(frequencies)
	if err != nil {
		t.Fatal(err)
	}
	for symbol, length := range code.lengths {
		if length != 8 {
			t.Fatalf("symbol %d length = %d, want 8", symbol, length)
		}
	}
}

func TestHuffmanLeafTiePriorityAndCanonicalOrder(t *testing.T) {
	code, err := buildHuffmanCode([]uint64{1, 1, 1, 1, 1})
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint8{3, 3, 2, 2, 2}; !slices.Equal(code.lengths, want) {
		t.Fatalf("lengths = %v, want %v", code.lengths, want)
	}
	reader := backwardFixture(0x1b70) // 00, 01, 10, 110, 111.
	for index, want := range []int{2, 3, 4, 0, 1} {
		got, err := code.decode(reader)
		if err != nil {
			t.Fatalf("decode %d: %v", index, err)
		}
		if got != want {
			t.Fatalf("decode %d = %d, want %d", index, got, want)
		}
	}
}

func TestAdaptiveHuffmanRebuildAndDilution(t *testing.T) {
	huffman, err := newAdaptiveHuffman(4, 2)
	if err != nil {
		t.Fatal(err)
	}
	reader := backwardFixture(0)
	for index := 0; index < 3; index++ {
		symbol, err := huffman.decode(reader)
		if err != nil {
			t.Fatal(err)
		}
		if symbol != 0 {
			t.Fatalf("symbol %d = %d, want 0", index, symbol)
		}
	}
	if want := []uint64{3, 1, 1, 1}; !slices.Equal(huffman.frequencies, want) {
		t.Fatalf("frequencies = %v, want %v", huffman.frequencies, want)
	}
	if huffman.decoded != 1 {
		t.Fatalf("decoded since rebuild = %d, want 1", huffman.decoded)
	}
}

func TestCanonicalHuffmanRejectsMalformedLengths(t *testing.T) {
	for _, lengths := range [][]uint8{{1, 1, 1}, {2, 2}, {0, 1}} {
		if _, err := canonicalHuffmanCode(lengths); err == nil {
			t.Fatalf("accepted malformed lengths %v", lengths)
		}
	}
	if _, err := newAdaptiveHuffman(1, 1); err == nil {
		t.Fatal("single-symbol adaptive alphabet accepted")
	}
}

func BenchmarkBuildAdaptiveHuffman256(b *testing.B) {
	frequencies := make([]uint64, 256)
	for index := range frequencies {
		frequencies[index] = uint64(1 + (index*37)%1024)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := buildHuffmanCode(frequencies); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRebuildAdaptiveHuffman256(b *testing.B) {
	frequencies := make([]uint64, 256)
	for index := range frequencies {
		frequencies[index] = uint64(1 + (index*37)%1024)
	}
	code, err := buildHuffmanCode(frequencies)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := code.rebuild(frequencies); err != nil {
			b.Fatal(err)
		}
	}
}
