package ibmisave

import (
	"bytes"
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestQualifiedDescriptorProfiles(t *testing.T) {
	for _, pair := range [][2]uint16{{0x4705, 0x3905}, {0x4600, 0x4600}, {0x3400, 0x3400}} {
		b := fixture()
		binary.BigEndian.PutUint16(b[0x52:], pair[0])
		binary.BigEndian.PutUint16(b[0x54:], pair[1])
		if pair[0] == 0x3400 {
			copy(b[0x1e0:0x1f0], b[0x280:0x290])
			clear(b[0x280:0x290])
			binary.BigEndian.PutUint64(b[0x108:], 0xabcdef00000011e0)
		}
		a, err := Open(&starfile.Bytes{Data: b}, 10)
		if err != nil || !a.CatalogPresent {
			t.Fatal(pair, a, err)
		}
	}
	b := fixture()
	binary.BigEndian.PutUint16(b[0x54:], 0x4600)
	if _, err := Open(&starfile.Bytes{Data: b}, 10); err == nil {
		t.Fatal("unqualified release pair")
	}
	b = fixture()
	copy(b[4:34], bytes.Repeat([]byte{0x40}, 30))
	copy(b[4:], []byte{0xd8, 0xc7, 0xc5, 0xd5, 0xc5, 0xe2, 0xc9, 0xe2, 0xe3})
	binary.BigEndian.PutUint16(b[34:], 0x19c1)
	if _, err := Open(&starfile.Bytes{Data: b}, 10); err == nil {
		t.Fatal("missing required catalog")
	}
	a, err := OpenProfile(&starfile.Bytes{Data: b}, 10, "boot750")
	if err != nil || a.CatalogPresent || a.Groups != 1 {
		t.Fatal(a, err)
	}
	b[4] = 0xc1
	if _, err := OpenProfile(&starfile.Bytes{Data: b}, 10, "boot750"); err == nil {
		t.Fatal("arbitrary catalog bypass")
	}
}
