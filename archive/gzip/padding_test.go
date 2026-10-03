package gzip

import (
	"bytes"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"testing"
)

func TestZeroPaddingWithoutHidingCorruption(t *testing.T) {
	a := encode(t, []byte("hello"))
	b := encode(t, []byte(" world"))
	for _, padding := range []int{1, 25, 65537} {
		src := append(append(bytes.Clone(a), b...), make([]byte, padding)...)
		f, e := Open(&starfile.Bytes{Data: src}, 11)
		if e != nil {
			t.Fatal(e)
		}
		if n, e := f.Validate(); n != 11 || e != nil {
			t.Fatal(n, e)
		}
		buf := make([]byte, 12)
		if n, e := f.ReadAt(buf, 0); n != 11 || e != io.EOF || string(buf[:n]) != "hello world" {
			t.Fatal(n, e, string(buf))
		}
	}
	corrupt := bytes.Clone(a)
	corrupt[len(corrupt)-8] ^= 1
	for _, src := range [][]byte{
		append(bytes.Clone(a), 0, 0, 1),
		append(bytes.Clone(a), 1),
		append(bytes.Clone(a), b[:10]...),
		append(append(bytes.Clone(a), 0), b...),
		append(corrupt, make([]byte, 25)...),
	} {
		f, e := Open(&starfile.Bytes{Data: src}, 0)
		if e == nil {
			_, e = f.Validate()
		}
		if e == nil {
			t.Fatal("corruption accepted")
		}
	}
}
