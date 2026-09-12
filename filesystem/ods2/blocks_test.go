package ods2

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func seal(b []byte) { le.PutUint16(b[510:], checksum(b[:510])) }
func headerFixture() []byte {
	b := make([]byte, 512)
	b[0], b[1] = 40, 100
	le.PutUint16(b[6:], 0x0201)
	le.PutUint16(b[8:], 137)
	le.PutUint16(b[10:], 1)
	le.PutUint16(b[26:], 5)
	le.PutUint16(b[30:], 6)
	b[58] = 5
	le.PutUint16(b[200:], 0x4301) // two blocks, LBN high six bits =3
	le.PutUint16(b[202:], 0x1234)
	le.PutUint16(b[204:], 0x8002) // three blocks, 32-bit LBN
	le.PutUint32(b[206:], 0x12345678)
	seal(b)
	return b
}
func TestHeader(t *testing.T) {
	b := headerFixture()
	h, err := DecodeHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID.Number != 137 || h.Size != 2560 || h.AllocatedBlocks != 5 || len(h.Extents) != 2 || h.Extents[0] != (Extent{LBN: 0x31234, Blocks: 2}) || h.Extents[1] != (Extent{LBN: 0x12345678, Blocks: 3}) {
		t.Fatal(h)
	}
	b[8] = 0
	if h.Raw[8] != 137 {
		t.Fatal("borrowed mutable header metadata")
	}
	for n := 0; n < 512; n++ {
		if _, err := DecodeHeader(b[:n]); err == nil {
			t.Fatal(n)
		}
	}
	for _, change := range []func([]byte){
		func(b []byte) { b[1] = 255; b[58] = 1 },
		func(b []byte) { b[58] = 1 },
		func(b []byte) { b[0] = 255 },
		func(b []byte) { le.PutUint16(b[32:], 512) },
		func(b []byte) { le.PutUint16(b[200:], 0) },
	} {
		bad := headerFixture()
		change(bad)
		seal(bad)
		if _, err := DecodeHeader(bad); err == nil {
			t.Fatal("accepted malformed header")
		}
	}
}

func TestLargeExtent(t *testing.T) {
	b := headerFixture()
	b[58] = 4
	le.PutUint16(b[200:], 0xc001)
	le.PutUint16(b[202:], 7)
	le.PutUint32(b[204:], 123456)
	seal(b)
	h, err := DecodeHeader(b)
	if err != nil || len(h.Extents) != 1 || h.Extents[0] != (Extent{LBN: 123456, Blocks: 65544}) {
		t.Fatal(h, err)
	}
	b[58] = 3
	seal(b)
	if _, err := DecodeHeader(b); err == nil {
		t.Fatal("truncated format3")
	}
}
func TestHome(t *testing.T) {
	disk := make([]byte, 10*512)
	b := disk[512:1024]
	le.PutUint32(b, 1)
	le.PutUint32(b[4:], 2)
	le.PutUint32(b[8:], 3)
	le.PutUint16(b[12:], 0x0201)
	le.PutUint16(b[14:], 1)
	le.PutUint16(b[22:], 5)
	le.PutUint32(b[24:], 4)
	le.PutUint32(b[28:], 100)
	le.PutUint16(b[32:], 1)
	copy(b[472:], "TEST        ")
	copy(b[496:], "DECFILE11B  ")
	le.PutUint16(b[58:], checksum(b[:58]))
	seal(b)
	h, err := ReadHome(&starfile.Bytes{Data: disk}, 1)
	if err != nil || h.BitmapLBN != 4 || h.MaximumFiles != 100 {
		t.Fatal(h, err)
	}
	for _, at := range []int{58, 100, 510} {
		b[at] ^= 1
		if _, err := ReadHome(&starfile.Bytes{Data: disk}, 1); err == nil {
			t.Fatal("checksum", at)
		}
		b[at] ^= 1
	}
}
func FuzzHeader(f *testing.F) {
	f.Add(headerFixture())
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeHeader(b) })
}
