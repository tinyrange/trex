package cfb

import (
	"bytes"
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"strings"
	"testing"
	"unicode/utf16"
)

func fixture() []byte {
	b := make([]byte, 13*512)
	p16 := func(off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
	p32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
	copy(b, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	p16(26, 3)
	p16(28, 0xfffe)
	p16(30, 9)
	p16(32, 6)
	p32(44, 1)
	p32(48, 1)
	p32(56, 4096)
	p32(60, 2)
	p32(64, 1)
	p32(68, end)
	for i := 76; i < 512; i += 4 {
		p32(i, free)
	}
	p32(76, 0)
	for i := 512; i < 1024; i += 4 {
		p32(i, free)
	}
	p32(512, 0xfffffffd)
	for i := 1; i <= 3; i++ {
		p32(512+4*i, end)
	}
	for i := 4; i < 11; i++ {
		p32(512+4*i, uint32(i+1))
	}
	p32(512+44, end)
	entry := func(id int, name string, kind byte, start, size, right, child uint32) {
		off := 1024 + 128*id
		units := utf16.Encode([]rune(name))
		for i, u := range units {
			p16(off+2*i, u)
		}
		p16(off+64, uint16(2*(len(units)+1)))
		b[off+66] = kind
		b[off+67] = 1
		p32(off+68, free)
		p32(off+72, right)
		p32(off+76, child)
		p32(off+116, start)
		p32(off+120, size)
	}
	entry(0, "Root Entry", 5, 3, 64, free, 1)
	entry(1, "Small", 2, 0, 5, 2, free)
	entry(2, "Large", 2, 4, 4096, free, free)
	for i := 1536; i < 2048; i += 4 {
		p32(i, free)
	}
	p32(1536, end)
	copy(b[2048:], "hello")
	for i := 2560; i < len(b); i++ {
		b[i] = byte((i - 2560) % 251)
	}
	return b
}
func TestCompoundStreams(t *testing.T) {
	b := fixture()
	a, err := Open(&starfile.Bytes{Data: b})
	if err != nil {
		t.Fatal(err)
	}
	small, err := starfile.ReadAll(a.Lookup("small"))
	if err != nil || string(small) != "hello" {
		t.Fatalf("small=%q %v", small, err)
	}
	large := a.Lookup("/LARGE")
	got := make([]byte, 1100)
	n, err := large.ReadAt(got, 499)
	if err != nil || n != len(got) || !bytes.Equal(got, b[2560+499:2560+1599]) {
		t.Fatal("cross-sector read", n, err)
	}
	n, err = large.ReadAt(make([]byte, 10), 4091)
	if n != 5 || err != io.EOF {
		t.Fatal("EOF contract", n, err)
	}
}
func TestMalformedCompoundChains(t *testing.T) {
	for _, tc := range []struct {
		name    string
		offset  int
		value   uint32
		message string
	}{
		{"FAT cycle", 512 + 44, 4, "cyclic"}, {"mini FAT cycle", 1536, 0, "cyclic"}, {"directory cycle", 1024 + 128 + 72, 1, "cyclic"}, {"out of range stream", 1024 + 256 + 116, 999, "invalid"}, {"truncated stream", 1024 + 256 + 120, 5000, "chain length"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := fixture()
			binary.LittleEndian.PutUint32(b[tc.offset:], tc.value)
			_, err := Open(&starfile.Bytes{Data: b})
			if err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestDeclaredDIFATWithFreeTerminator(t *testing.T) {
	b := make([]byte, 113*512)
	copy(b, fixture()[:512])
	put := func(offset int, value uint32) { binary.LittleEndian.PutUint32(b[offset:], value) }
	put(44, 110)
	put(48, 110)
	put(60, end)
	put(64, 0)
	put(68, 111)
	put(72, 1)
	for i := 0; i < 109; i++ {
		put(76+i*4, uint32(i))
	}
	for offset := 512; offset < 111*512; offset += 4 {
		put(offset, free)
	}
	for i := 0; i < 110; i++ {
		put(512+i*4, 0xfffffffd)
	}
	put(512+110*4, end)
	put(512+111*4, 0xfffffffc)
	copy(b[111*512:], fixture()[1024:1152])
	put(111*512+76, free)
	put(111*512+116, end)
	put(111*512+120, 0)
	for offset := 112 * 512; offset < len(b); offset += 4 {
		put(offset, free)
	}
	put(112*512, 109)
	if _, err := Open(&starfile.Bytes{Data: b}); err != nil {
		t.Fatal(err)
	}
	put(44, 111)
	if _, err := Open(&starfile.Bytes{Data: b}); err == nil {
		t.Fatal("accepted mismatched FAT count")
	}
}
