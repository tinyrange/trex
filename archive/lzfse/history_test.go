package lzfse

import (
	"bytes"
	"testing"
)

func TestLZVNCrossBlockHistory(t *testing.T) {
	// The first explicit match references the preceding stored block, then
	// reuses its distance with overlap. A cold random read must replay history.
	stream := append([]byte("bvx-"), 3, 0, 0, 0, 'a', 'b', 'c')
	tokens := []byte{0, 3, 0xf3, 6, 0, 0, 0, 0, 0, 0, 0}
	h := make([]byte, 12)
	copy(h, "bvxn")
	le.PutUint32(h[4:], 6)
	le.PutUint32(h[8:], uint32(len(tokens)))
	stream = append(stream, h...)
	stream = append(stream, tokens...)
	stream = append(stream, []byte("bvx$")...)
	f, err := Open(bytes.NewReader(stream), 0)
	if err != nil {
		t.Fatal(err)
	}
	var got [5]byte
	if _, err := f.ReadAt(got[:], 4); err != nil || string(got[:]) != "bcabc" {
		t.Fatalf("cross-block read %q: %v", got, err)
	}
	delete(f.cache, 1)
	f.cached -= 6
	if _, err := f.ReadAt(got[:], 4); err != nil || string(got[:]) != "bcabc" {
		t.Fatalf("uncached replay %q: %v", got, err)
	}
}

func TestV1CountsCannotOverflowHostInt(t *testing.T) {
	for _, off := range []int{12, 16} {
		stream := append(entropyFixture(false, 1, 3, 1), []byte("bvx$")...)
		le.PutUint32(stream[off:], 0xfffffffc)
		if _, err := Open(bytes.NewReader(stream), 0); err == nil {
			t.Fatalf("accepted oversized v1 count at %d", off)
		}
	}
}
