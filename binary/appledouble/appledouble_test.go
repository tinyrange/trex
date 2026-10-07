package appledouble

import (
	"bytes"
	"encoding/binary"
	"testing"
)

type source []byte

func (s source) Size() int64                             { return int64(len(s)) }
func (s source) ReadAt(b []byte, off int64) (int, error) { return bytes.NewReader(s).ReadAt(b, off) }
func TestForksRemainSeparateAndBorrowed(t *testing.T) {
	b := make(source, 86)
	be := binary.BigEndian
	be.PutUint32(b, 0x51607)
	be.PutUint32(b[4:], 0x20000)
	be.PutUint16(b[24:], 2)
	be.PutUint32(b[26:], 9)
	be.PutUint32(b[30:], 50)
	be.PutUint32(b[34:], 32)
	be.PutUint32(b[38:], 2)
	be.PutUint32(b[42:], 82)
	be.PutUint32(b[46:], 4)
	copy(b[82:], "fork")
	entries, err := Open(b)
	if err != nil || len(entries) != 2 {
		t.Fatalf("%v %v", entries, err)
	}
	b[82] = 'F'
	got := make([]byte, 4)
	entries[1].Data.ReadAt(got, 0)
	if string(got) != "Fork" {
		t.Fatal("copied resource fork")
	}
	be.PutUint32(b[42:], 81)
	if _, err := Open(b); err == nil {
		t.Fatal("accepted overlap")
	}
	be.PutUint32(b[42:], 82)
	be.PutUint32(b[38:], 9)
	if _, err := Open(b); err == nil {
		t.Fatal("accepted duplicate ID")
	}
}
