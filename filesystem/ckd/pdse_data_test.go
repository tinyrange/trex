package ckd

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

func dataFixture(payloads ...[]byte) ([]byte, []byte) {
	b := bytes.Repeat([]byte{0x7f}, 8192) // Nonzero stale allocation must not become data.
	info := make([]byte, 85)
	info[0] = 1
	var pos, total, largest int
	for _, p := range payloads {
		copy(b[pos:], []byte{0xc3, 0, 0, 0, byte(len(p) >> 8), byte(len(p))})
		copy(b[pos+6:], p)
		pos += 6 + len(p)
		total += len(p)
		largest = max(largest, len(p))
	}
	be.PutUint64(info[28:], uint64(total))
	be.PutUint32(info[48:], uint32(len(payloads)))
	be.PutUint32(info[52:], 1)
	be.PutUint32(info[56:], 2)
	be.PutUint32(info[60:], uint32(largest))
	be.PutUint32(info[64:], uint32(len(payloads)))
	return b, info
}

func TestPDSEDataCrossPageRecordsAndEOF(t *testing.T) {
	a := bytes.Repeat([]byte{0x40}, 4087)
	z := []byte{0xc3, 0, 0, 0, 0, 80, 0xff} // Header-like payload is not a delimiter.
	b, info := dataFixture(a, nil, z)
	c, sizes, err := OpenPDSEData(raw(b), info, 0x50, 4096, 3)
	if err != nil || !reflect.DeepEqual(sizes, []uint32{4087, 0, 7}) {
		t.Fatal(sizes, err)
	}
	want := append(bytes.Clone(a), z...)
	got := make([]byte, len(want)+10)
	n, err := c.ReadAt(got, 0)
	if n != len(want) || err != io.EOF || !bytes.Equal(got[:n], want) {
		t.Fatal(n, err)
	}
	for _, offset := range []int64{4080, 4086, 4087, 4093} {
		got := make([]byte, 3)
		n, err := c.ReadAt(got, offset)
		end := min(len(want), int(offset)+3)
		if !bytes.Equal(got[:n], want[offset:end]) || (end < int(offset)+3 && err != io.EOF) {
			t.Fatal(offset, n, err)
		}
	}
	if _, _, err := OpenPDSEData(raw(b), info, 0x50, 4096, 2); err == nil {
		t.Fatal("budget ignored")
	}
	for _, offset := range []int{28, 48, 52, 56, 60, 64} {
		bad := bytes.Clone(info)
		bad[offset] ^= 1
		if _, _, err := OpenPDSEData(raw(b), bad, 0x50, 4096, 3); err == nil {
			t.Fatal("corrupt descriptor accepted", offset)
		}
	}
	b[4093] = 0xff // Second header straddles a page boundary.
	if _, _, err := OpenPDSEData(raw(b), info, 0x50, 4096, 3); err == nil {
		t.Fatal("bad frame accepted")
	}
}

func TestPDSEDataFixedAndEmpty(t *testing.T) {
	b, info := dataFixture([]byte("abcd"), []byte("efgh"))
	c, _, err := OpenPDSEData(raw(b), info, 0x90, 4, 2)
	if err != nil || c.Size() != 8 {
		t.Fatal(c, err)
	}
	if _, _, err := OpenPDSEData(raw(b), info, 0x90, 5, 2); err == nil {
		t.Fatal("wrong LRECL accepted")
	}
	if _, _, err := OpenPDSEData(raw(b), info, 0x50, 7, 2); err == nil {
		t.Fatal("oversized variable record accepted")
	}
	b, info = dataFixture()
	c, sizes, err := OpenPDSEData(raw(b), info, 0x90, 80, 1)
	if err != nil || c.Size() != 0 || len(sizes) != 0 {
		t.Fatal(c, sizes, err)
	}
}
