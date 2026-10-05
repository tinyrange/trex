package storage

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type countedReader struct {
	data  []byte
	reads int
	short bool
}

func (c *countedReader) Size() int64 { return int64(len(c.data)) }
func (c *countedReader) ReadAt(p []byte, off int64) (int, error) {
	c.reads++
	if c.short {
		return 0, nil
	}
	if off >= int64(len(c.data)) {
		return 0, io.EOF
	}
	n := copy(p, c.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func TestCompositeLazyRangesAndErrors(t *testing.T) {
	a := &countedReader{data: []byte("abcdef")}
	b := &countedReader{data: []byte("XYZ")}
	c, e := Compose(Range{Source: a, Offset: 1, Length: 3}, Range{Source: b, Length: 3}, Range{Source: a, Offset: 5, Length: 1})
	if e != nil {
		t.Fatal(e)
	}
	if a.reads+b.reads != 0 {
		t.Fatal("compose eagerly read data")
	}
	buf := make([]byte, 5)
	if n, e := c.ReadAt(buf, 2); n != 5 || e != nil || string(buf) != "dXYZf" {
		t.Fatal(n, e, string(buf))
	}
	if n, e := c.ReadAt(make([]byte, 8), 0); n != 7 || e != io.EOF {
		t.Fatal(n, e)
	}
	var out bytes.Buffer
	if n, e := c.WriteTo(&out); n != 7 || e != nil || out.String() != "bcdXYZf" {
		t.Fatal(n, e, out.String())
	}
	if _, e := Compose(Range{Source: a, Offset: 4, Length: 3}); e == nil {
		t.Fatal("invalid range accepted")
	}
	a.short = true
	if _, e := c.ReadAt(buf, 0); !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatal("short read silently accepted", e)
	}
}
