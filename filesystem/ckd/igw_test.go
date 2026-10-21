package ckd

import (
	"bytes"
	"testing"
)

func attributeFixture() []byte {
	b := make([]byte, 4096)
	b[0], b[1], b[11], b[12], b[25], b[30] = 52, 1, 0xc1, 0xc4, 20, 2
	// A nonzero lower-bound anchor, retained by the first completely compressed key.
	b[24] = 24 // Internal-page header metadata is not part of the key-width byte.
	b[57] = 3
	be.PutUint16(b[4094:], 0xa55a)
	cells := [][]byte{
		{0, 9, 0xc0, 20, 0, 0, 0, 0, 4},
		{0, 10, 0xc0, 9, 10, 0x12, 0, 0, 0, 43},
	}
	pos := 72
	for _, c := range cells {
		be.PutUint16(b[pos:], uint16(5+len(c)))
		be.PutUint16(b[pos+2:], uint16(5+len(c)))
		b[pos+4] = 1
		copy(b[pos+5:], c)
		pos += 5 + len(c)
	}
	be.PutUint16(b[48:], uint16(3950-pos))
	be.PutUint16(b[50:], 3950)
	// Deliberately plausible stale data in the free region must never be parsed.
	copy(b[pos:], []byte{0, 14, 0, 14, 1, 0, 9, 0xc0, 20, 0, 0, 0, 0, 99})
	return b
}

func TestAttributePageAnchorsPaddingAndFreeSpace(t *testing.T) {
	b := attributeFixture()
	p, err := ParseAttributePage(b)
	if err != nil {
		t.Fatal(err)
	}
	if p.Level != 2 || len(p.Cells) != 2 {
		t.Fatalf("%+v", p)
	}
	if p.Cells[0].Key[5] != 3 || p.Cells[1].Key[5] != 3 || p.Cells[1].Key[9] != 0x12 || !bytes.Equal(p.Cells[1].Key[10:], make([]byte, 10)) {
		t.Fatal(p.Cells)
	}
	if !bytes.Equal(p.Cells[0].Value, []byte{0, 0, 0, 4}) || !bytes.Equal(p.Cells[1].Value, []byte{0, 0, 0, 43}) {
		t.Fatal(p.Cells)
	}
	for _, flag := range []byte{0xd5, 0xec} {
		b[79] = flag
		variant, err := ParseAttributePage(b)
		if err != nil || variant.Cells[0].Flags != flag {
			t.Fatal(variant, err)
		}
	}
	clear(b)
	if p.Cells[0].Value[3] != 4 || p.Cells[1].Key[9] != 0x12 {
		t.Fatal("page aliases input")
	}
}

func TestAttributePageRejectsMalformedCompression(t *testing.T) {
	for _, n := range []int{0, 51, 4095} {
		if _, err := ParseAttributePage(attributeFixture()[:n]); err == nil {
			t.Fatal("short page", n)
		}
	}
	for _, tc := range []struct {
		name  string
		off   int
		value byte
	}{
		{"signature", 11, 0}, {"trailer", 4095, 0}, {"free count", 48, 255},
		{"limit", 50, 255}, {"group size", 72, 255}, {"used size", 74, 255},
		{"cell count", 76, 2}, {"cell length", 78, 4}, {"flags", 79, 0},
		{"prefix", 80, 21}, {"padding", 81, 1},
		{"short suffix", 80, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := attributeFixture()
			b[tc.off] = tc.value
			if _, err := ParseAttributePage(b); err == nil {
				t.Fatal("malformed page accepted")
			}
		})
	}
}
