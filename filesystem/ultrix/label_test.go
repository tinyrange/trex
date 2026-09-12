package ultrix

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func fixture(order binary.ByteOrder) []byte {
	b := make([]byte, 64*512)
	l := b[31*512+440:]
	order.PutUint32(l, 0x32957)
	order.PutUint32(l[4:], 1)
	order.PutUint32(l[8:], 4)
	order.PutUint32(l[12:], 40)
	order.PutUint32(l[24:], 64)
	copy(b[40*512:], "DATA")
	return b
}
func TestLabelViews(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		b := fixture(order)
		p, err := Open(&starfile.Bytes{Data: b})
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 8 || p[1].Data != nil || p[2].Data.Size() != int64(len(b)) {
			t.Fatal(p)
		}
		var got [4]byte
		if _, err := starfile.ReadFullAt(p[0].Data, got[:], 0); err != nil || string(got[:]) != "DATA" {
			t.Fatal(got, err)
		}
	}
}
func TestLabelRejectsInvalid(t *testing.T) {
	for _, change := range []func([]byte){
		func(b []byte) { b[31*512+440] = 0 },
		func(b []byte) { b[31*512+444] = 0 },
		func(b []byte) { binary.LittleEndian.PutUint32(b[31*512+448:], 65) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[31*512+452:], 0xffffffff) },
	} {
		b := fixture(binary.LittleEndian)
		change(b)
		if _, err := Open(&starfile.Bytes{Data: b}); err == nil {
			t.Fatal("accepted malformed label")
		}
	}
	b := fixture(binary.LittleEndian)
	if _, err := Open(&starfile.Bytes{Data: b[:16383]}); err == nil {
		t.Fatal("accepted truncation")
	}
}
