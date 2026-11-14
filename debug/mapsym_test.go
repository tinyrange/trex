package debug

import (
	"encoding/binary"
	"testing"
)

func mapSymFixture() []byte {
	b := make([]byte, 164)
	put := func(p int, v uint16) { binary.LittleEndian.PutUint16(b[p:], v) }
	put(0, 10)
	b[2] = 1
	put(6, 1)
	put(8, 24)
	put(10, 1)
	put(12, 4)
	b[15] = 3
	copy(b[16:], "MOD")
	put(24, 32)
	binary.LittleEndian.PutUint32(b[32:], 0x12345678)
	b[36] = 3
	copy(b[37:], "abs")
	// Segment's next pointer deliberately loops to itself, a supported MAPSYM convention.
	put(64, 4)
	put(66, 2)
	put(68, 32)
	put(70, 7)
	b[84] = 4
	copy(b[85:], "CODE")
	put(96, 40)
	put(98, 48)
	put(104, 0xfffe)
	b[106] = 3
	copy(b[107:], "one")
	put(112, 0x1234)
	b[114] = 3
	copy(b[115:], "two")
	b[162] = 1
	b[163] = 5
	return b
}

func TestMapSymbols(t *testing.T) {
	b := mapSymFixture()
	s, err := ReadMapSymbols(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 3 || s[0] != (MapSymbol{"MOD", "", "abs", 0, 0x12345678}) || s[1] != (MapSymbol{"MOD", "CODE", "one", 7, 0xfffe}) || s[2].Offset != 0x1234 {
		t.Fatalf("unexpected symbols: %#v", s)
	}
	// Segment bitness is independent of its load address and absolute-symbol width.
	b[78] = 1
	binary.LittleEndian.PutUint32(b[104:], 0x87654321)
	b[108] = 1
	b[109] = 'x'
	binary.LittleEndian.PutUint32(b[112:], 0x10203040)
	b[116] = 1
	b[117] = 'y'
	s, err = ReadMapSymbols(b)
	if err != nil || s[1].Offset != 0x87654321 || s[2].Name != "y" {
		t.Fatalf("32-bit symbols: %#v %v", s, err)
	}
}

func TestMapSymbolsRejectMalformed(t *testing.T) {
	b := mapSymFixture()
	for n := 0; n < len(b); n++ {
		if _, err := ReadMapSymbols(b[:n]); err == nil {
			t.Fatalf("accepted truncated input at %d", n)
		}
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[163] = 99 },
		func(b []byte) { binary.LittleEndian.PutUint16(b, 1) },      // next map overlaps first map
		func(b []byte) { binary.LittleEndian.PutUint16(b[10:], 2) }, // repeated segment
		func(b []byte) { binary.LittleEndian.PutUint16(b[68:], 0xffff) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[96:], 0xffff) },
		func(b []byte) { b[106] = 255 },
	} {
		c := append([]byte(nil), b...)
		mutate(c)
		if _, err := ReadMapSymbols(c); err == nil {
			t.Fatal("accepted malformed map")
		}
	}
}

func FuzzMapSymbols(f *testing.F) {
	f.Add(mapSymFixture())
	f.Fuzz(func(t *testing.T, b []byte) { ReadMapSymbols(b) })
}
