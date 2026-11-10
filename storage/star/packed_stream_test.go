package star

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestPackStreamBoundariesOwnershipAndFailure(t *testing.T) {
	s, err := NewPackedFileStore(0, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 1, 4095, 65535, 65536, 65537, 200000} {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i/71 + i/1000)
		}
		want := bytes.Clone(data)
		f, err := s.PackStream("stream", int64(size), func(w io.Writer) error {
			for off := 0; off < len(data); {
				n := min(113, len(data)-off)
				if _, err := w.Write(data[off : off+n]); err != nil {
					return err
				}
				clear(data[off : off+n]) // writer must consume, not retain caller buffers
				off += n
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, size)
		if _, err := ReadFullAt(f, got, 0); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
	sentinel := errors.New("producer failure")
	for _, produce := range []func(io.Writer) error{
		func(w io.Writer) error { return sentinel },
		func(w io.Writer) error { _, err := w.Write([]byte{1}); return err },
		// Ignored writer errors must still prevent publication.
		func(w io.Writer) error { w.Write([]byte{1, 2, 3}); return nil },
	} {
		f, err := s.PackStream("bad", 2, produce)
		if err == nil || f != nil {
			t.Fatal("published incomplete/failed file")
		}
	}
	if _, err := s.PackStream("negative", -1, func(io.Writer) error { return nil }); err == nil {
		t.Fatal("negative size")
	}
}
