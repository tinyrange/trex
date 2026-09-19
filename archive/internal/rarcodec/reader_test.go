package rarcodec

import (
	"bytes"
	"io"
	"testing"
)

// A filter spans the window boundary; filling its second half queues another
// filter. Queued offsets must include the bytes already buffered from window 1.
type crossingDecoder struct{ filled bool }

func (d *crossingDecoder) init(byteReader, bool, int64, int) {}
func (d *crossingDecoder) version() int                      { return decode29Ver }
func (d *crossingDecoder) fill(r *decodeReader) error {
	if d.filled {
		return io.EOF
	}
	d.filled = true
	for _, b := range []byte("abcd") {
		r.writeByte(b)
	}
	if e := r.queueFilter(&filterBlock{length: 1, filter: upper}); e != nil {
		return e
	}
	for _, b := range []byte("efgh") {
		r.writeByte(b)
	}
	return nil
}
func upper(b []byte, _ int64) ([]byte, error) { return bytes.ToUpper(b), nil }
func TestFilterCrossingWindowKeepsQueuedOffsets(t *testing.T) {
	r := &decodeReader{win: []byte("......xy"), size: 8, r: 6, w: 8, dec: &crossingDecoder{}, fl: []*filterBlock{{length: 4, filter: upper}}}
	got, e := io.ReadAll(r)
	if e != nil || string(got) != "XYABcdEfgh" {
		t.Fatalf("%q: %v", got, e)
	}
}
func TestResourceBounds(t *testing.T) {
	var r Reader
	if e := r.Reset(bytes.NewReader(nil), 29, 65<<20, 1, false); e != ErrMemoryLimit {
		t.Fatal(e)
	}
	if e := r.Reset(bytes.NewReader([]byte{0xa0, 0xff}), 29, 1<<20, 1, false); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Read(make([]byte, 1)); e != ErrMemoryLimit {
		t.Fatal(e)
	}
}

func TestQueuedFilterDistanceCanExceedWindow(t *testing.T) {
	r := &decodeReader{size: 8, r: 0, w: 7}
	f := &filterBlock{offset: 3, length: 1, filter: upper}
	if e := r.queueFilter(f); e != nil {
		t.Fatal(e)
	}
	if f.offset != 10 {
		t.Fatalf("relative offset wrapped to %d, want 10", f.offset)
	}
}

func TestLZMatchContinuesAcrossWindow(t *testing.T) {
	r := &decodeReader{win: []byte("ABCDEFGH"), size: 8, r: 6, w: 6, dec: &crossingDecoder{filled: true}}
	r.copyBytes(5, 2)
	got, e := io.ReadAll(r)
	if e != nil || string(got) != "EFEFE" {
		t.Fatalf("%q: %v", got, e)
	}
}
