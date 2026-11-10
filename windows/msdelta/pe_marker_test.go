package msdelta

import (
	"math/rand/v2"
	"testing"
)

func (m peMarker) values() []byte {
	values := make([]byte, m.size)
	for i := range values {
		values[i] = m.get(i)
	}
	return values
}

func TestPEMarkerAgainstByteOwnership(t *testing.T) {
	rng := rand.New(rand.NewPCG(20, 41))
	for _, size := range []int{0, 1, 31, 32, 33, 63, 64, 65, 4097} {
		marker := newPEMarker(size)
		want := make([]byte, size)
		for step := 0; step < 1000; step++ {
			start, end := rng.IntN(size+128)-64, rng.IntN(size+128)-64
			set, clear := byte(rng.IntN(4)), byte(rng.IntN(4))
			marker.update(start, end, set, clear)
			for i := max(0, start); i < min(size, end); i++ {
				want[i] = (want[i] &^ clear) | set
			}
			for i, value := range want {
				if marker.get(i) != value {
					t.Fatalf("size%d step%d range%d:%d index%d got%d want%d", size, step, start, end, i, marker.get(i), value)
				}
			}
		}
		if len(marker.words)*8 > (size+31)/32*8 {
			t.Fatal("ownership map not compact")
		}
	}
}

func BenchmarkPEMarkerNonExecutable(b *testing.B) {
	marker := newPEMarker(64 << 20)
	layout := peLayout{sections: []peSection{{rawStart: 4096, rawSize: 32 << 20, characteristics: 0x20000000}}}
	b.SetBytes(int64(marker.size))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		markNonExecutablePE(marker, layout)
	}
}
