package zstd

import (
	"bytes"
	"encoding/binary"
	codec "github.com/klauspost/compress/zstd"
	"io"
	"testing"
)

type testSource struct{ *bytes.Reader }

func (s testSource) Size() int64 { return s.Reader.Size() }
func TestFramesAndReadAt(t *testing.T) {
	plain := bytes.Repeat([]byte("bounded portable zstd stream\n"), 10000)
	enc, e := codec.NewWriter(nil, codec.WithEncoderCRC(true))
	if e != nil {
		t.Fatal(e)
	}
	defer enc.Close()
	data := enc.EncodeAll(plain, nil)
	skip := make([]byte, 11)
	binary.LittleEndian.PutUint32(skip, 0x184d2a50)
	binary.LittleEndian.PutUint32(skip[4:], 3)
	frames := append(append(append([]byte{}, skip...), data...), data...)
	want := append(append([]byte{}, plain...), plain...)
	f, e := Open(testSource{bytes.NewReader(frames)}, 0)
	if e != nil {
		t.Fatal(e)
	}
	if f.Size() != int64(len(want)) {
		t.Fatal(f.Size())
	}
	for _, off := range []int{0, 65530, len(plain) - 5, len(want) - 15, 0} {
		p := make([]byte, 32)
		n, e := f.ReadAt(p, int64(off))
		expected := min(len(p), len(want)-off)
		if n != expected || !bytes.Equal(p[:n], want[off:off+n]) {
			t.Fatalf("offset %d n%d err%v", off, n, e)
		}
		if n < 32 && e != io.EOF {
			t.Fatal(e)
		}
	}
	var out bytes.Buffer
	if _, e = f.WriteTo(&out); e != nil || !bytes.Equal(out.Bytes(), want) {
		t.Fatal(e)
	}
	corrupt := append([]byte{}, data...)
	corrupt[len(corrupt)-1] ^= 1
	f, e = Open(testSource{bytes.NewReader(corrupt)}, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.WriteTo(io.Discard); e == nil {
		t.Fatal("accepted checksum corruption")
	}
	for _, n := range []int{1, 4, 7, len(data) - 1} {
		if _, e = Open(testSource{bytes.NewReader(data[:n])}, 0); e == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
}
func TestStreamingFrame(t *testing.T) {
	var compressed bytes.Buffer
	enc, e := codec.NewWriter(&compressed)
	if e != nil {
		t.Fatal(e)
	}
	plain := bytes.Repeat([]byte("unknown-size "), 20000)
	enc.Write(plain)
	if e = enc.Close(); e != nil {
		t.Fatal(e)
	}
	f, e := Open(testSource{bytes.NewReader(compressed.Bytes())}, 0)
	if e != nil {
		t.Fatal(e)
	}
	if f.Size() != int64(len(plain)) {
		t.Fatal(f.Size())
	}
	var out bytes.Buffer
	if _, e = f.WriteTo(&out); e != nil || !bytes.Equal(out.Bytes(), plain) {
		t.Fatal(e)
	}
}
