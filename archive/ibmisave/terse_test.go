package ibmisave

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func terseFixture(codes []uint16, want int) []byte {
	// The external code stream includes a zero end code and byte-alignment fill.
	codes = append(append([]uint16(nil), codes...), 0)
	b := make([]byte, 12+(len(codes)*12+7)/8)
	binary.BigEndian.PutUint32(b, 0x02000080)
	binary.BigEndian.PutUint32(b[4:], uint32(len(b)))
	binary.BigEndian.PutUint32(b[8:], uint32(want))
	for i, c := range codes {
		for j := 0; j < 12; j++ {
			if c&(1<<uint(11-j)) != 0 {
				bit := i*12 + j
				b[12+bit/8] |= 1 << uint(7-bit%8)
			}
		}
	}
	return b
}
func TestTersePresetAndSelfExtension(t *testing.T) {
	b := terseFixture([]uint16{277, 4095, 4094}, 66)
	out, info, err := DecodeTerseWithInfo(b)
	if err != nil || !info.TerminationVerified || !bytes.Equal(out, bytes.Repeat([]byte{0x40}, 66)) {
		t.Fatal(info, err)
	}
	for _, edit := range []func([]byte){func(b []byte) { b[len(b)-1] = 1 }, func(b []byte) { b[7]++ }, func(b []byte) { b[11]++ }, func(b []byte) { b[12] = 0 }} {
		bad := bytes.Clone(b)
		edit(bad)
		_, i, e := DecodeTerseWithInfo(bad)
		if e == nil && i.TerminationVerified {
			t.Fatal("accepted corruption")
		}
	}
}
func TestTerseLRUSaturation(t *testing.T) {
	// Touch the first phrase shortly before initial allocation is exhausted.
	// It must survive recycling, unlike blindly decrementing/wrapping codes.
	codes := []uint16{66, 67}
	want := []byte{'A', 'B'}
	for i := 0; i < 3800; i++ {
		codes = append(codes, 68)
		want = append(want, 'C')
	}
	codes = append(codes, 4095)
	want = append(want, 'A', 'B')
	for i := 0; i < 200; i++ {
		codes = append(codes, 69)
		want = append(want, 'D')
	}
	codes = append(codes, 4095)
	want = append(want, 'A', 'B')
	out, info, err := DecodeTerseWithInfo(terseFixture(codes, len(want)))
	if err != nil || !info.DictionaryFull || !info.TerminationVerified || !bytes.Equal(out, want) {
		t.Fatal(info, err)
	}
}
func TestTransportNestedSaveAndIsolation(t *testing.T) {
	plain := fixture()
	codes := make([]uint16, len(plain))
	for i, b := range plain {
		codes[i] = uint16(b) + 1
	}
	frame := terseFixture(codes, len(plain))
	tag := make([]byte, 14)
	copy(tag, terseTag)
	binary.BigEndian.PutUint16(tag[8:], uint16(len(plain)))
	binary.BigEndian.PutUint16(tag[12:], uint16(len(frame)))
	src := append(bytes.Clone(plain), tag...)
	src = append(src, frame...)
	tail := make([]byte, 17)
	copy(tail, lzTag)
	binary.BigEndian.PutUint16(tail[12:], 3)
	copy(tail[14:], "raw")
	src = append(src, tail...)
	tr, err := OpenOpticalTransport(&starfile.Bytes{Data: src}, 100, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Complete || tr.UnknownTail.Size() != 17 || tr.LogicalBytes != 2*int64(len(plain)) {
		t.Fatal(tr)
	}
	tr.Records[1].ExpandedSize = 1 // Exposed metadata cannot corrupt the reader.
	a, err := Open(adapter.File(tr.Data), 100)
	if err != nil || len(a.Objects) != 2 {
		t.Fatal(a, err)
	}
	n := auto.Open(&starfile.Bytes{Data: src}, "", auto.Options{})
	child, err := n.Resolve("logical-prefix.bin/save1/QSRDSSPC.1/occurrence2/sections/1.bin")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 14)
	if _, err := child.Reader().ReadAt(got, 0); err != nil || string(got) != "stored section" {
		t.Fatal(string(got), err)
	}
	for _, limit := range []int64{0, int64(len(plain))} {
		if _, err := OpenOpticalTransport(&starfile.Bytes{Data: src}, 100, limit); err == nil {
			t.Fatal("budget")
		}
	}
	src[len(plain)+10] = 1
	if _, err := OpenOpticalTransport(&starfile.Bytes{Data: src}, 100, 1<<20); err == nil {
		t.Fatal("reserved field")
	}
}
func FuzzTerse(f *testing.F) {
	f.Add(terseFixture([]uint16{277, 4095, 4094}, 66))
	f.Fuzz(func(t *testing.T, b []byte) {
		out, info, err := DecodeTerseWithInfo(b)
		if err == nil && (len(out) == 0 || len(out) > 65535 || info.ConsumedBits > max(0, len(b)-12)*8) {
			t.Fatal("unbounded result")
		}
	})
}
