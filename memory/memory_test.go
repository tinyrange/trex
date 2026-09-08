package memory

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type source struct{ *bytes.Reader }

func (s source) Size() int64 { return s.Reader.Size() }
func physical(t *testing.T, data []byte, ranges []Range) *Physical {
	t.Helper()
	p, err := NewPhysical(source{bytes.NewReader(data)}, ranges)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func fault(t *testing.T, err error, kind, level string) {
	t.Helper()
	var f *Fault
	if !errors.As(err, &f) || f.Kind != kind || f.Level != level {
		t.Fatalf("fault = %v, want %s/%s", err, kind, level)
	}
}
func TestSparse(t *testing.T) {
	ranges := []Range{{Start: 8, Offset: 2, Size: 2}, {Start: 0, Size: 2}}
	p := physical(t, []byte{0, 0, 3, 4}, ranges)
	ranges[1].Size = 1
	data, err := Read(p, 0, 3)
	fault(t, err, "not-captured", "physical")
	if !bytes.Equal(data, []byte{0, 0}) {
		t.Fatal(data)
	}
	data, err = Read(p, 8, 2)
	if err != nil || !bytes.Equal(data, []byte{3, 4}) {
		t.Fatal(data, err)
	}
	_, err = Read(p, 10, 1)
	fault(t, err, "not-captured", "physical")
	empty := physical(t, []byte{1}, []Range{})
	_, err = Read(empty, 0, 1)
	fault(t, err, "not-captured", "physical")
	for _, r := range [][]Range{{{Size: 0}}, {{Size: 5}}, {{Size: 2}, {Start: 1, Size: 1}}, {{Start: 1 << 63, Size: 1}}} {
		if _, err := NewPhysical(source{bytes.NewReader(make([]byte, 4))}, r); err == nil {
			t.Fatal("invalid ranges accepted", r)
		}
	}
}
func TestX86(t *testing.T) {
	data := make([]byte, 0x6000)
	put := func(off int, v uint32) { binary.LittleEndian.PutUint32(data[off:], v) }
	put(0x1000, 0x2001)
	put(0x2000, 0x3001)
	put(0x2004, 0x5001)
	data[0x3fff], data[0x5000] = 42, 43
	p := physical(t, data, nil)
	x, _ := NewX86(p, 0x1000, false)
	got, err := Read(x, 4095, 2)
	if err != nil || !bytes.Equal(got, []byte{42, 43}) {
		t.Fatal(got, err)
	}
	tr, err := x.Translate(4096)
	if err != nil || tr.Physical != 0x5000 || len(tr.Entries) != 2 {
		t.Fatal(tr, err)
	}
	_, err = x.Translate(8192)
	fault(t, err, "not-present", "pte")
	_, err = x.Translate(1 << 22)
	fault(t, err, "not-present", "pde")
	_, err = x.Translate(1 << 32)
	fault(t, err, "invalid-address", "virtual")
	put(0x1000, 0x400081)
	tr, err = x.Translate(123)
	if err != nil || tr.Physical != 0x40007b || tr.PageSize != 1<<22 {
		t.Fatal(tr, err)
	}
	_, err = Read(x, 123, 1)
	fault(t, err, "not-captured", "data")
	put(0x1000, 0x402081)
	_, err = x.Translate(0)
	fault(t, err, "unsupported", "pse-36")
	sparse := physical(t, data, []Range{{Start: 0x1000, Offset: 0x1000, Size: 4}})
	put(0x1000, 0x2001)
	x, _ = NewX86(sparse, 0x1000, false)
	_, err = x.Translate(0)
	fault(t, err, "not-captured", "pte")
}
func TestPAE(t *testing.T) {
	data := make([]byte, 0x5000)
	put := func(off int, v uint64) { binary.LittleEndian.PutUint64(data[off:], v) }
	put(0x1000, 0x2001)
	put(0x2000, 0x3001)
	put(0x3000, 0x100000001)
	data[0x4000] = 99
	p := physical(t, data, []Range{{Size: 0x4000}, {Start: 1 << 32, Offset: 0x4000, Size: 0x1000}})
	x, _ := NewX86(p, 0x1000, true)
	got, err := Read(x, 0, 1)
	if err != nil || got[0] != 99 {
		t.Fatal(got, err)
	}
	tr, err := x.Translate(0)
	if err != nil || len(tr.Entries) != 3 {
		t.Fatal(tr, err)
	}
	put(0x2000, 0x200081)
	tr, err = x.Translate(17)
	if err != nil || tr.Physical != 0x200011 || tr.PageSize != 1<<21 {
		t.Fatal(tr, err)
	}
	_, err = x.Translate(1 << 30)
	fault(t, err, "not-present", "pdpte")
}

type broken struct{}

func (broken) Size() int64                       { return 4096 }
func (broken) ReadAt([]byte, int64) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestSourceError(t *testing.T) {
	p, _ := NewPhysical(broken{}, nil)
	x, _ := NewX86(p, 0, false)
	_, err := x.Translate(0)
	fault(t, err, "source-error", "pde")
}
