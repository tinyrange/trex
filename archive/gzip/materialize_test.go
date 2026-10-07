package gzip

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

type guardedSource struct {
	data      []byte
	forbidden bool
	reads     int
}

func (s *guardedSource) Size() int64 { return int64(len(s.data)) }
func (s *guardedSource) ReadAt(p []byte, off int64) (int, error) {
	s.reads++
	if s.forbidden {
		return 0, errors.New("compressed source consulted after materialization")
	}
	return bytes.NewReader(s.data).ReadAt(p, off)
}
func TestMaterializeIndependentRandomAccessAndIntegrity(t *testing.T) {
	data := bytes.Repeat([]byte("borrowed random-access package bytes"), 100000)
	source := &guardedSource{data: encode(t, data)}
	source.data = append(source.data, encode(t, []byte("tail"))...)
	source.data = append(source.data, 0, 0, 0)
	r, err := Materialize(source, int64(len(data)+4))
	if err != nil {
		t.Fatal(err)
	}
	source.forbidden = true
	reads := source.reads
	want := append(data, []byte("tail")...)
	for _, off := range []int64{int64(len(data)) - 10, 0, 1000000, 13} {
		var got [14]byte
		if _, err := r.ReadAt(got[:], off); err != nil || !bytes.Equal(got[:], want[off:off+14]) {
			t.Fatal(off, err)
		}
	}
	if source.reads != reads || r.Size() != int64(len(want)) {
		t.Fatal("replayed source or incorrect size")
	}
	if n, err := r.ReadAt(make([]byte, 8), r.Size()-4); n != 4 || err != io.EOF {
		t.Fatal(n, err)
	}
	bad := bytes.Clone(encode(t, data))
	bad[len(bad)-8] ^= 1
	for _, encoded := range [][]byte{bad, bad[:len(bad)-3]} {
		if r, err := Materialize(&starfile.Bytes{Data: encoded}, int64(len(data))); r != nil || err == nil {
			t.Fatal("invalid stream returned", r, err)
		}
	}
	if r, err := Materialize(&starfile.Bytes{Data: encode(t, data)}, int64(len(data)-1)); r != nil || !errors.Is(err, auto.ErrLimit) {
		t.Fatal(r, err)
	}
	if r, err := Materialize(source, 0); r != nil || err == nil {
		t.Fatal("unbounded cache", r, err)
	}
}
