package channel

import (
	"errors"
	"io"
	"testing"
)

func TestMemoryPairBoundariesAndCheckpoint(t *testing.T) {
	a, b, err := NewMemoryPair(4)
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 4)
	if _, err := b.Read(p); !errors.Is(err, ErrWouldBlock) {
		t.Fatalf("empty read: %v", err)
	}
	if n, err := a.Write([]byte("abcd")); err != nil || n != 4 {
		t.Fatalf("write: %d %v", n, err)
	}
	if _, err := a.Write([]byte("x")); !errors.Is(err, ErrWouldBlock) {
		t.Fatalf("overflow: %v", err)
	}
	restore, err := a.CaptureCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 2; iteration++ {
		if n, err := b.Read(p[:2]); err != nil || n != 2 || string(p[:2]) != "ab" {
			t.Fatalf("partial: %d %q %v", n, p, err)
		}
		a.Close()
		if n, err := b.Read(p); err != nil || n != 2 || string(p[:2]) != "cd" {
			t.Fatalf("drain: %d %q %v", n, p, err)
		}
		if _, err := b.Read(p); err != io.EOF {
			t.Fatalf("EOF: %v", err)
		}
		if err := restore(); err != nil {
			t.Fatal(err)
		}
	}
}
