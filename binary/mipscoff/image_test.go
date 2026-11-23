package mipscoff

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func imageFixture() *starfile.Bytes {
	const sectionTable = 76
	const dataOffset = 156
	b := make([]byte, 176+18+4+16)
	le := binary.LittleEndian
	le.PutUint16(b, 0x162)
	le.PutUint16(b[2:], 2)
	le.PutUint32(b[8:], 176)
	le.PutUint32(b[12:], 1)
	le.PutUint16(b[16:], 56)
	le.PutUint16(b[20:], 0x107)
	le.PutUint32(b[36:], 0x80030000)
	copy(b[sectionTable:], ".text")
	le.PutUint32(b[sectionTable+12:], 0x80030000)
	le.PutUint32(b[sectionTable+16:], 20)
	le.PutUint32(b[sectionTable+20:], dataOffset)
	le.PutUint32(b[sectionTable+36:], 0x20)
	copy(b[116:], ".bss")
	le.PutUint32(b[128:], 0x80031000)
	le.PutUint32(b[132:], 8)
	le.PutUint32(b[152:], 0x400)
	le.PutUint32(b[dataOffset:], 0x1234)
	le.PutUint32(b[180:], 4)
	le.PutUint32(b[184:], 0x80030000)
	le.PutUint16(b[188:], 1)
	le.PutUint32(b[194:], 20)
	copy(b[198:], "KiSystemStartup\x00")
	return &starfile.Bytes{Data: b}
}

func TestROMCOFFLoadAndSymbols(t *testing.T) {
	source := imageFixture()
	im, err := Open(source)
	if err != nil {
		t.Fatal(err)
	}
	if im.Entry != 0x80030000 || len(im.Sections) != 2 || !im.Sections[1].ZeroFill() {
		t.Fatalf("bad image %+v", im)
	}
	out := []byte{0xaa, 0xaa, 0xaa, 0xaa}
	if err = im.ReadSection(0, 0, out); err != nil || binary.LittleEndian.Uint32(out) != 0x1234 {
		t.Fatalf("text %x, %v", out, err)
	}
	if err = im.ReadSection(1, 4, out); err != nil || binary.LittleEndian.Uint32(out) != 0 {
		t.Fatalf("BSS %x, %v", out, err)
	}
	symbols, err := im.Symbols()
	if err != nil || len(symbols) != 1 || symbols[0].Name != "KiSystemStartup" || symbols[0].Address != im.Entry {
		t.Fatalf("symbols %+v, %v", symbols, err)
	}
}

func TestROMCOFFRejectsAliasedSections(t *testing.T) {
	f := imageFixture()
	binary.LittleEndian.PutUint32(f.Data[128:], 0xa0030000)
	if _, err := Open(f); err == nil {
		t.Fatal("accepted physically overlapping KSEG aliases")
	}
}
