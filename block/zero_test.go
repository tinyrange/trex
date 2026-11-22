package block

import (
	"bytes"
	"testing"
)

func TestZeroDeviceHugeSparseRange(t *testing.T) {
	d, err := NewZeroDevice(1<<50, 512)
	if err != nil {
		t.Fatal(err)
	}
	b := bytes.Repeat([]byte{7}, 512)
	if n, err := d.ReadAt(b, 1<<50-512); err != nil || n != 512 || !bytes.Equal(b, make([]byte, 512)) {
		t.Fatal("large sparse read", n, err)
	}
	if _, err := d.ReadAt(b, 1<<50); err != ErrOutOfRange {
		t.Fatal("out-of-range read", err)
	}
	e, err := d.Extents(1<<40, 8192)
	if err != nil || len(e) != 1 || e[0].Allocated || e[0].Length != 8192 {
		t.Fatal("blank extents", e, err)
	}
	if d.Capabilities().Writable {
		t.Fatal("zero base advertised writable")
	}
	for _, size := range []int64{-1, 513} {
		if _, err := NewZeroDevice(size, 512); err == nil {
			t.Fatal("invalid geometry", size)
		}
	}
}
