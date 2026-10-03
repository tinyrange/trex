package ckd

import (
	"bytes"
	"testing"
)

func TestStoredProgramDoesNotInventEOF(t *testing.T) {
	b := make([]byte, 4096)
	copy(b, eb("IEWPLMH", 8))
	b[12] = 4
	be.PutUint32(b[8:], 48)
	be.PutUint32(b[16:], 8192)
	be.PutUint32(b[20:], 2)
	be.PutUint16(b[24:], 6)
	be.PutUint32(b[28:], 48)
	be.PutUint32(b[32:], 20)
	be.PutUint16(b[36:], 7)
	be.PutUint32(b[40:], 4096)
	be.PutUint32(b[44:], 3000)
	copy(b[48:], eb("IEWLIDX", 8))
	copy(b[len(b)-4:], []byte("TAIL"))
	stored, e := OpenStoredProgramObject(raw(b))
	if e != nil {
		t.Fatal(e)
	}
	if stored.Size() != 4096 {
		t.Fatal("invented expanded EOF", stored.Size())
	}
	got := make([]byte, 4096)
	if _, e := stored.ReadAt(got, 0); e != nil || !bytes.Equal(got, b) {
		t.Fatal(e)
	}
	bad := bytes.Clone(b)
	be.PutUint32(bad[28:], 8190)
	if _, e := OpenStoredProgramObject(raw(bad)); e == nil {
		t.Fatal("truncated metadata accepted")
	}
	be.PutUint32(bad[28:], 48)
	be.PutUint32(bad[44:], 5000)
	if _, e := OpenStoredProgramObject(raw(bad)); e == nil {
		t.Fatal("section beyond declared extent accepted")
	}
}
