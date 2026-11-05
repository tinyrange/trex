package msdelta

import (
	"bytes"
	"fmt"
	"testing"
)

func TestHuffmanLookupMatchesCheckedDecoder(t *testing.T) {
	trees := [][]byte{{1, 1}, {1, 0, 0}, {2, 2}, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16}, defaultHuffmanLengths(mainSymbols)}
	for _, lengths := range trees {
		h, err := newHuffman(lengths, 16)
		if err != nil {
			t.Fatal(err)
		}
		// Exhaust every prefix, including unused codes, and every truncation of
		// the reservoir. The reference consumes exactly one checked bit at a time.
		for n := uint(0); n <= 16; n++ {
			for prefix := uint64(0); prefix < 1<<n; prefix++ {
				a := bitReader{value: prefix, bitCount: n}
				b := a
				got, ge := h.decode(&a)
				want, we := h.decodeSlow(&b)
				if got != want || fmt.Sprint(ge) != fmt.Sprint(we) || a.value != b.value || a.bitCount != b.bitCount {
					t.Fatalf("lengths %v, %d bits prefix %x: got %d/%v/%+v want %d/%v/%+v", lengths, n, prefix, got, ge, a, want, we, b)
				}
			}
		}
		// Exercise refills and non-byte-aligned final padding as well.
		for pad := byte(0); pad < 8; pad++ {
			data := bytes.Repeat([]byte{0x96, 0x37, 0xcb}, 100)
			data[0] = data[0]&^7 | pad
			a, _ := newBitReader(data)
			b, _ := newBitReader(data)
			for {
				got, ge := h.decode(a)
				want, we := h.decodeSlow(b)
				if got != want || fmt.Sprint(ge) != fmt.Sprint(we) {
					t.Fatalf("refill: %d/%v != %d/%v", got, ge, want, we)
				}
				if ge != nil {
					break
				}
			}
		}
	}
}

func TestCombinedMatchSpansAndOverlap(t *testing.T) {
	for sourceSize := 0; sourceSize < 9; sourceSize++ {
		source := []byte("abcdefghi")[:sourceSize]
		for targetSize := 0; targetSize < 9; targetSize++ {
			initial := []byte("JKLMNOPQR")[:targetSize]
			for start := -1; start <= sourceSize+targetSize; start++ {
				for length := uint32(0); length < 80; length++ {
					got := append([]byte(nil), initial...)
					want := append([]byte(nil), initial...)
					invalid := false
					pos := start
					for range length {
						if pos < 0 || pos >= len(source)+len(want) {
							invalid = true
							break
						}
						if pos < len(source) {
							want = append(want, source[pos])
						} else {
							want = append(want, want[pos-len(source)])
						}
						pos++
					}
					err := appendCombinedMatch(&got, source, start, length)
					if (err != nil) != invalid || !bytes.Equal(got, want) {
						t.Fatalf("source=%d target=%d start=%d length=%d: got %x/%v want %x invalid=%v", sourceSize, targetSize, start, length, got, err, want, invalid)
					}
				}
			}
		}
	}
}

func BenchmarkHuffmanDecode(b *testing.B) {
	h, _ := newHuffman(defaultHuffmanLengths(mainSymbols), 16)
	for _, fast := range []bool{false, true} {
		b.Run(fmt.Sprint(fast), func(b *testing.B) {
			r := bitReader{}
			for i := 0; i < b.N; i++ {
				if r.bitCount < 16 {
					r.value = 0x9673cb9673cb9673
					r.bitCount = 64
				}
				if fast {
					_, _ = h.decode(&r)
				} else {
					_, _ = h.decodeSlow(&r)
				}
			}
		})
	}
}
