package lzx

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestBitReaderWordBoundaries(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for trial := 0; trial < 100; trial++ {
		var w lzxTestBitWriter
		var widths []uint
		var values []uint32
		for i := 0; i < 100; i++ {
			n := uint(rng.Intn(33))
			v := rng.Uint32() & uint32((uint64(1)<<n)-1)
			w.writeBits(v, n)
			widths = append(widths, n)
			values = append(values, v)
		}
		r := newLZXBitReader(w.bytes())
		for i, n := range widths {
			if got := r.readBits(n); got != values[i] || r.err != nil {
				t.Fatalf("trial %d read %d width %d: %x want %x: %v", trial, i, n, got, values[i], r.err)
			}
		}
	}
}

func TestHuffmanCanonicalCodes(t *testing.T) {
	// A complete, maximally skewed tree exercises every code length and both
	// sides of the fast-table boundary, starting at every word-bit position.
	lens := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16}
	for start := uint(0); start < 16; start++ {
		var w lzxTestBitWriter
		w.writeBits(0, start)
		for repeat := 0; repeat < 3; repeat++ {
			for sym := range lens {
				lzxTestWriteSymbol(&w, lens, sym)
			}
		}
		h, err := newLZXHuffman(lens)
		if err != nil {
			t.Fatal(err)
		}
		br := newLZXBitReader(w.bytes())
		br.readBits(start)
		for repeat := 0; repeat < 3; repeat++ {
			for want := range lens {
				got, err := h.decode(br)
				if err != nil || got != want {
					t.Fatalf("start %d: got %d want %d: %v", start, got, want, err)
				}
			}
		}
	}
}

func TestHuffmanRandomCanonicalTrees(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	var h lzxHuffman
	for trial := 0; trial < 100; trial++ {
		lens := []byte{1, 1}
		for leaves := 2 + rng.Intn(600); len(lens) < leaves; {
			i := rng.Intn(len(lens))
			if lens[i] == 16 {
				continue
			}
			lens[i]++
			lens = append(lens, lens[i])
		}
		rng.Shuffle(len(lens), func(i, j int) { lens[i], lens[j] = lens[j], lens[i] })
		var w lzxTestBitWriter
		for sym := range lens {
			lzxTestWriteSymbol(&w, lens, sym)
		}
		if err := h.reset(lens); err != nil {
			t.Fatal(err)
		}
		br := newLZXBitReader(w.bytes())
		for want := range lens {
			got, err := h.decode(br)
			if err != nil || got != want {
				t.Fatalf("trial %d: got %d want %d: %v", trial, got, want, err)
			}
		}
	}
	if err := h.reset([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.decode(newLZXBitReader([]byte{0xff, 0xff})); err == nil {
		t.Fatal("reused table retained a stale code")
	}
}

func TestHuffmanShortCodeAtEOF(t *testing.T) {
	h, _ := newLZXHuffman([]byte{1, 1})
	br := newLZXBitReader([]byte{0xff, 0xff})
	br.readBits(15)
	if sym, err := h.decode(br); sym != 1 || err != nil {
		t.Fatalf("last bit: %d %v", sym, err)
	}
	if _, err := h.decode(br); err == nil {
		t.Fatal("accepted missing bit")
	}
	long, _ := newLZXHuffman([]byte{16})
	br = newLZXBitReader([]byte{0, 0})
	br.readBits(1)
	if _, err := long.decode(br); err == nil {
		t.Fatal("accepted truncated long code")
	}
}

func TestHuffmanInvalidTreesAndCodes(t *testing.T) {
	for _, lens := range [][]byte{{17}, {1, 1, 1}, {1, 2, 2, 2}} {
		if _, err := newLZXHuffman(lens); err == nil {
			t.Fatalf("accepted lengths %v", lens)
		}
	}
	for _, lens := range [][]byte{{}, {0, 0}, {1}} {
		h, err := newLZXHuffman(lens)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.decode(newLZXBitReader([]byte{0xff, 0xff})); err == nil {
			t.Fatalf("accepted missing code for %v", lens)
		}
	}
}

func TestHuffmanLookaheadDoesNotConsumeRawBytes(t *testing.T) {
	h, _ := newLZXHuffman([]byte{1, 1})
	for start := uint(0); start < 16; start++ {
		br := newLZXBitReader([]byte{0, 0, 0xaa, 0xbb, 0xcc, 0xdd})
		br.readBits(start)
		if _, err := h.decode(br); err != nil {
			t.Fatal(err)
		}
		br.align16Always()
		want := []byte{0xaa, 0xbb}
		if start == 15 {
			want = []byte{0xcc, 0xdd}
		} // whole padding word
		if got := br.takeBytes(2); !bytes.Equal(got, want) {
			t.Fatalf("start %d: %x want %x", start, got, want)
		}
	}
}
