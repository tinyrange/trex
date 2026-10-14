package decmpfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"testing"
)

func TestStoredInlineBorrowedAndBounds(t *testing.T) {
	b := make([]byte, 17)
	copy(b, "fpmc")
	binary.LittleEndian.PutUint32(b[4:], 9)
	binary.LittleEndian.PutUint64(b[8:], 3)
	b[16] = 0xcc
	b = append(b, []byte("abc")...)
	f, kind, err := Open(bytes.NewReader(b), nil)
	if err != nil || kind != 9 {
		t.Fatalf("open %d %v", kind, err)
	}
	b[17] = 'A'
	got := make([]byte, 5)
	if n, err := f.ReadAt(got, 1); n != 2 || err != io.EOF || string(got[:n]) != "bc" {
		t.Fatalf("partial %q %v", got, err)
	}
	if _, err := f.ReadAt(got[:3], 0); err != nil || string(got[:3]) != "Abc" {
		t.Fatalf("borrowed %q %v", got, err)
	}
	for _, edit := range []func([]byte) []byte{
		func(b []byte) []byte { b[16] = 0; return b },
		func(b []byte) []byte { return b[:len(b)-1] },
		func(b []byte) []byte { return append(b, 0) },
		func(b []byte) []byte { binary.LittleEndian.PutUint64(b[8:], ^uint64(0)); return b },
	} {
		bad := edit(append([]byte(nil), b...))
		if _, _, err := Open(bytes.NewReader(bad), nil); err == nil {
			t.Fatal("accepted malformed stored inline")
		}
	}
}

func TestResourceAllocationTailAndZlibValidation(t *testing.T) {
	plain := bytes.Repeat([]byte("native bytes"), 100)
	var packed bytes.Buffer
	z := zlib.NewWriter(&packed)
	if _, err := z.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	b := append(append([]byte(nil), packed.Bytes()...), bytes.Repeat([]byte{0xa5}, 342)...)
	got, err := inflate(bytes.NewReader(b), 0, int64(len(b)), int64(len(plain)), true)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("resource tail: %v", err)
	}
	if _, err := inflate(bytes.NewReader(b), 0, int64(len(b)), int64(len(plain)), false); err == nil {
		t.Fatal("inline framing accepted allocation tail")
	}
	if _, err := inflate(bytes.NewReader(b), 0, int64(len(b)), int64(len(plain)-1), true); err == nil {
		t.Fatal("ignored logical length")
	}
	b[packed.Len()-1] ^= 1
	if _, err := inflate(bytes.NewReader(b), 0, int64(len(b)), int64(len(plain)), true); err == nil {
		t.Fatal("ignored zlib checksum")
	}
}
