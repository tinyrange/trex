package ziparchive

import (
	"bytes"
	"testing"
)

func TestImplodeBoundedReplay(t *testing.T) {
	// An all-zero stream bigger than Entry's window; references to the initial
	// dictionary are legal and avoid a large synthetic compressed fixture.
	size := decodedWindow + 65537
	raw := []byte{3, 0xf5, 0xf5, 0xf5, 0xf5, 3, 0xf5, 0xf5, 0xf5, 0xf5}
	w := new(testBits)
	for left := size; left > 0; {
		if left == 1 {
			w.put(1, 1)
			w.put(0, 8)
			left--
			continue
		}
		length := min(left, 320)
		w.put(0, 1)
		w.put(0, 6)
		w.put(63, 6) // match, low distance 0, high symbol 0
		if length >= 65 {
			w.put(0, 6)
			w.put(uint64(length-65), 8)
		} else {
			code := length - 2
			for i := 5; i >= 0; i-- {
				w.put(uint64(1-((code>>i)&1)), 1)
			}
		}
		left -= length
	}
	raw = append(raw, w.finish()...)
	want := make([]byte, size)
	_, f := legacyFixture(t, raw, want, 6, 0)
	for _, off := range []int{size - 101, 7, size - 103, 0} {
		got := make([]byte, 91)
		if n, err := f.ReadAt(got, int64(off)); err != nil || n != len(got) || !bytes.Equal(got, make([]byte, len(got))) {
			t.Fatalf("replay %d: %d %v", off, n, err)
		}
		if len(f.data) > decodedWindow || cap(f.data) > 2*decodedWindow {
			t.Fatal("unbounded legacy window")
		}
	}
	if err := f.Verify(); err != nil {
		t.Fatal(err)
	}
}
func TestShrinkRejectsClearedPreviousCycle(t *testing.T) {
	// A freshly cleared previous leaf must not form a self-referential chain.
	_, f := legacyFixture(t, shrinkCodes(65, 66, 257, 256, 2, 257), make([]byte, 100), 1, 0)
	if err := f.Verify(); err == nil {
		t.Fatal("accepted cyclic clear/previous-code stream")
	}
}
