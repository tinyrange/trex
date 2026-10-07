package bzip2

import (
	"bytes"
	std "compress/bzip2"
	"errors"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"testing"
)

type guardedSource struct {
	data      []byte
	forbidden bool
}

func (s *guardedSource) Size() int64 { return int64(len(s.data)) }
func (s *guardedSource) ReadAt(p []byte, off int64) (int, error) {
	if s.forbidden {
		return 0, errors.New("replayed compressed source")
	}
	return bytes.NewReader(s.data).ReadAt(p, off)
}
func TestMaterializeIntegrityAndIndependentAccess(t *testing.T) {
	encoded := append(multi(t, 4), vector(t, helloHex)...)
	want, err := io.ReadAll(std.NewReader(bytes.NewReader(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	source := &guardedSource{data: encoded}
	cached, err := Materialize(source, int64(len(want)))
	if err != nil {
		t.Fatal(err)
	}
	source.forbidden = true
	for _, off := range []int64{int64(len(want)) - 16, 0, 100, 13} {
		var got [16]byte
		if _, err := cached.ReadAt(got[:], off); err != nil || !bytes.Equal(got[:], want[off:off+16]) {
			t.Fatal(off, err)
		}
	}
	if cached.Size() != int64(len(want)) {
		t.Fatal("snapshot size")
	}
	bad := bytes.Clone(encoded)
	bad[len(bad)-3] ^= 1
	for _, raw := range [][]byte{bad, encoded[:len(encoded)-3]} {
		if r, err := Materialize(&starfile.Bytes{Data: raw}, int64(len(want))); r != nil || err == nil {
			t.Fatal("invalid stream returned a snapshot", err)
		}
	}
	if r, err := Materialize(&starfile.Bytes{Data: encoded}, int64(len(want)-1)); r != nil || !errors.Is(err, auto.ErrLimit) {
		t.Fatal("limit not enforced", err)
	}
	if r, err := Materialize(&starfile.Bytes{Data: encoded}, 0); r != nil || err == nil {
		t.Fatal("unbounded materialization")
	}
}
