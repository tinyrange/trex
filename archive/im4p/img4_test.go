package im4p

import (
	"bytes"
	"io"
	"testing"
)

func TestIMG4WrapBorrowsAndPreservesRecords(t *testing.T) {
	p := fixture()
	manifest := []byte{0x30, 6, 0x16, 4, 'I', 'M', '4', 'M'}
	for _, m := range [][]byte{nil, manifest} {
		var mr *bytes.Reader
		if m != nil {
			mr = bytes.NewReader(m)
		}
		var r interface {
			Size() int64
			ReadAt([]byte, int64) (int, error)
		}
		var err error
		if mr == nil {
			r, err = Wrap(bytes.NewReader(p), nil)
		} else {
			r, err = Wrap(bytes.NewReader(p), mr)
		}
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		root, end, err := node(r, 0, r.Size(), 0, &count)
		if err != nil || end != r.Size() {
			t.Fatalf("container %v", err)
		}
		magic, _ := text(root.Children[0])
		if magic != "IMG4" || len(root.Children) != 2+len(m)/8 {
			t.Fatal("bad wrapper")
		}
		got, _ := io.ReadAll(io.NewSectionReader(root.Children[1].Raw, 0, root.Children[1].Raw.Size()))
		if !bytes.Equal(got, p) {
			t.Fatal("payload changed")
		}
		if m != nil && root.Children[2].Tag != 0xa0 {
			t.Fatal("manifest not explicit context zero")
		}
	}
	if _, err := Wrap(bytes.NewReader(p), bytes.NewReader(p)); err == nil {
		t.Fatal("accepted IM4P as manifest")
	}
	for _, n := range []uint64{127, 128, 255, 256, 65535, 65536} {
		h := derHeader(4, n)
		b := append(h, make([]byte, n)...)
		_, width, size, err := header(bytes.NewReader(b), 0, int64(len(b)))
		if err != nil || size != int64(n) || width != int64(len(h)) {
			t.Fatalf("length %d: %v", n, err)
		}
	}
}
