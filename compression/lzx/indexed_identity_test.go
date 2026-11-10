package lzx

import (
	"bytes"
	"testing"
)

func TestLZXIndexedRejectsChangedDeferredFrame(t *testing.T) {
	plain := bytes.Repeat([]byte{0x55}, 4*lzxFrameSize)
	input := lzxTestUncompressedStream(plain)
	r, err := NewIndexedReader(bytes.NewReader(input), int64(len(input)), 15, len(plain), 32768)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 100)
	if _, err := r.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	r.ReleaseReadCache()
	// This all-literal stream has no restart after its only format block.
	// A changed source must not silently redefine a published member's bytes.
	input[len(input)-500] ^= 1
	if _, err := r.ReadAt(got, int64(len(plain)-550)); err == nil {
		t.Fatal("changed deferred bytes accepted")
	}
}
