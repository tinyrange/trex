package burn

import (
	"debug/pe"
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func fixture(signed bool) ([]byte, []byte) {
	h := make([]byte, 48)
	b := make([]byte, 512)
	put := binary.LittleEndian.PutUint32
	put(h, 0x00f14300)
	put(h[4:], 2)
	put(h[24:], 128)
	put(h[40:], 1)
	put(h[44:], 2)
	put(b[48:], 36)
	put(b[52:], 36)
	second := 164
	if signed {
		put(h[32:], 164)
		put(h[36:], 64)
		second = 228
	}
	for _, off := range []int{128, second} {
		copy(b[off:], "MSCF")
		put(b[off+8:], 36)
	}
	return h, b
}
func TestSignedAndUnsignedContainers(t *testing.T) {
	for _, signed := range []bool{false, true} {
		h, b := fixture(signed)
		got, err := containers(&starfile.Bytes{Data: b}, h, 48, 8, pe.DataDirectory{})
		if err != nil {
			t.Fatal(err)
		}
		want := int64(164)
		if signed {
			want = 228
		}
		if len(got) != 2 || got[0].(*starfile.Slice).Offset != 128 || got[1].(*starfile.Slice).Offset != want {
			t.Fatalf("wrong offsets: %v", got)
		}
	}
}
func TestRejectMalformedContainers(t *testing.T) {
	for _, name := range []string{"count", "truncated", "cabsize", "overlap", "version", "format"} {
		t.Run(name, func(t *testing.T) {
			h, b := fixture(true)
			put := binary.LittleEndian.PutUint32
			switch name {
			case "count":
				put(h[44:], 0xffffffff)
			case "truncated":
				b = b[:240]
			case "cabsize":
				put(b[236:], 37)
			case "overlap":
				put(h[32:], 1)
			case "version":
				put(h[4:], 3)
			case "format":
				put(h[40:], 2)
			}
			if _, err := containers(&starfile.Bytes{Data: b}, h, 48, 8, pe.DataDirectory{}); err == nil {
				t.Fatal("accepted malformed input")
			}
		})
	}
}
func TestCertificateFallback(t *testing.T) {
	h, b := fixture(true)
	binary.LittleEndian.PutUint32(h[32:], 0)
	got, err := containers(&starfile.Bytes{Data: b}, h, 48, 8, pe.DataDirectory{VirtualAddress: 164, Size: 64})
	if err != nil || got[1].(*starfile.Slice).Offset != 228 {
		t.Fatalf("certificate fallback: %v %v", got, err)
	}
}
