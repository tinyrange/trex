package irix

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func elfFixture(class int, o binary.ByteOrder) []byte {
	b := make([]byte, 1024)
	copy(b, "\x7fELF")
	b[6] = 1
	b[5] = 2
	if o == binary.LittleEndian {
		b[5] = 1
	}
	width, header, phw, shw := 4, 52, 32, 40
	b[4] = 1
	if class == 64 {
		width, header, phw, shw = 8, 64, 56, 64
		b[4] = 2
	}
	put := func(b []byte, n uint64) {
		if width == 4 {
			o.PutUint32(b, uint32(n))
		} else {
			o.PutUint64(b, n)
		}
	}
	o.PutUint16(b[16:], 2)
	o.PutUint16(b[18:], 8)
	o.PutUint32(b[20:], 1)
	put(b[24:], 0x1100)
	put(b[24+width:], uint64(header))
	put(b[24+2*width:], 640)
	tail := 24 + 3*width
	flags := uint32(0x20000020)
	if class == 64 {
		flags = 0x20000000
	}
	o.PutUint32(b[tail:], flags)
	o.PutUint16(b[tail+4:], uint16(header))
	o.PutUint16(b[tail+6:], uint16(phw))
	o.PutUint16(b[tail+8:], 2)
	o.PutUint16(b[tail+10:], uint16(shw))
	o.PutUint16(b[tail+12:], 6)
	o.PutUint16(b[tail+14:], 5)
	segment := func(dst []byte, typ uint32, off, addr, size uint64) {
		o.PutUint32(dst, typ)
		if width == 4 {
			put(dst[4:], off)
			put(dst[8:], addr)
			put(dst[16:], size)
			put(dst[20:], size)
			o.PutUint32(dst[24:], 5)
			put(dst[28:], 1)
		} else {
			o.PutUint32(dst[4:], 5)
			put(dst[8:], off)
			put(dst[16:], addr)
			put(dst[32:], size)
			put(dst[40:], size)
			put(dst[48:], 1)
		}
	}
	segment(b[header:], 1, 0, 0x1000, 1024)
	segment(b[header+phw:], 2, 288, 0x1120, uint64(width*8))
	for i, pair := range [][2]uint64{{5, 0x11c0}, {10, 13}, {1, 5}, {0, 0}} {
		put(b[288+i*width*2:], pair[0])
		put(b[288+i*width*2+width:], pair[1])
	}
	names := []byte("\x00.text\x00.strtab\x00.symtab\x00.rel.text\x00.shstrtab\x00")
	copy(b[400:], names)
	copy(b[448:], "\x00foo\x00libc.so\x00")
	symw := 16
	relw := 8
	reltype := uint32(9)
	if class == 64 {
		symw, relw, reltype = 24, 24, 4
	}
	for i, s := range []struct {
		name, typ         uint32
		off, size, stride uint64
		link, info        uint32
	}{{0, 0, 0, 0, 0, 0, 0}, {1, 1, 256, 4, 0, 0, 0}, {7, 3, 448, 13, 0, 0, 0}, {15, 2, 480, uint64(symw * 2), uint64(symw), 2, 1}, {23, reltype, 544, uint64(relw), uint64(relw), 3, 1}, {33, 3, 400, uint64(len(names)), 0, 0, 0}} {
		dst := b[640+i*shw:]
		o.PutUint32(dst, s.name)
		o.PutUint32(dst[4:], s.typ)
		put(dst[8+2*width:], s.off)
		put(dst[8+3*width:], s.size)
		o.PutUint32(dst[8+4*width:], s.link)
		o.PutUint32(dst[12+4*width:], s.info)
		put(dst[16+5*width:], s.stride)
	}
	symbol := b[480+symw:]
	o.PutUint32(symbol, 1)
	if width == 4 {
		put(symbol[4:], 0x1100)
		symbol[12] = 0x12
		o.PutUint16(symbol[14:], 1)
	} else {
		symbol[4] = 0x12
		o.PutUint16(symbol[6:], 1)
		put(symbol[8:], 0x1100)
	}
	put(b[544:], 0x1100)
	if width == 4 {
		o.PutUint32(b[548:], 1<<8|5)
	} else {
		o.PutUint32(b[552:], 1)
		b[556], b[557], b[558], b[559] = 2, 5, 24, 18
		o.PutUint64(b[560:], ^uint64(7))
	}
	copy(b[256:], "code")
	return b
}
func TestELFGenerations(t *testing.T) {
	for _, class := range []int{32, 64} {
		for _, o := range []binary.ByteOrder{binary.BigEndian, binary.LittleEndian} {
			b := elfFixture(class, o)
			im, err := Open(&starfile.Bytes{Data: b})
			if err != nil {
				t.Fatal(class, o, err)
			}
			expectedABI := "n32"
			if class == 64 {
				expectedABI = "n64"
			}
			if im.Class != class || im.ABI != expectedABI || im.ISA != "mips3" || im.Entry != 0x1100 || len(im.Symbols) != 2 || im.Symbols[1].Name != "foo" || len(im.Libraries) != 1 || im.Libraries[0] != "libc.so" {
				t.Fatalf("decoded wrong image: %+v", im)
			}
			independent, err := elf.NewFile(bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			symbols, err := independent.Symbols()
			if err != nil {
				t.Fatal(err)
			}
			if independent.Entry != im.Entry || symbols[0].Value != im.Symbols[1].Value || symbols[0].Name != im.Symbols[1].Name {
				t.Fatal("disagrees with independent ELF parser")
			}
			r := im.Relocations[0]
			if r.Symbol != 1 {
				t.Fatal(r)
			}
			if class == 64 {
				if r.Types != [3]byte{18, 24, 5} || r.SpecialSymbol != 2 || r.Addend != -8 {
					t.Fatal("bad MIPS triple relocation", r)
				}
			} else if r.Types[0] != 5 || r.HasAddend {
				t.Fatal(r)
			}
		}
	}
}
func TestELFBounds(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"table":             func(b []byte) { binary.BigEndian.PutUint32(b[32:], 0xffffff00) },
		"load size":         func(b []byte) { binary.BigEndian.PutUint32(b[52+16:], 2048) },
		"symbol link":       func(b []byte) { binary.BigEndian.PutUint32(b[640+3*40+24:], 99) },
		"relocation symbol": func(b []byte) { binary.BigEndian.PutUint32(b[548:], 2<<8|5) },
		"string":            func(b []byte) { binary.BigEndian.PutUint32(b[496:], 999) },
		"null dynamic":      func(b []byte) { binary.BigEndian.PutUint32(b[312:], 1) },
		"abi":               func(b []byte) { binary.BigEndian.PutUint32(b[36:], 0x1020) },
	} {
		t.Run(name, func(t *testing.T) {
			b := elfFixture(32, binary.BigEndian)
			mutate(b)
			if _, err := Open(&starfile.Bytes{Data: b}); err == nil {
				t.Fatal("accepted malformed ELF")
			}
		})
	}
	b := elfFixture(32, binary.BigEndian)
	for _, n := range []int{0, 19, 51, 400, 700} {
		if _, err := Open(&starfile.Bytes{Data: b[:n]}); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
}
func ecoffFixture(o binary.ByteOrder) []byte {
	b := make([]byte, 640)
	magic := uint16(0x160)
	if o == binary.LittleEndian {
		magic = 0x162
	}
	o.PutUint16(b, magic)
	o.PutUint16(b[2:], 2)
	o.PutUint16(b[16:], 56)
	o.PutUint16(b[18:], 7)
	o.PutUint16(b[20:], 0x107)
	o.PutUint32(b[36:], 0x80001000)
	o.PutUint32(b[72:], 0x80003000)
	copy(b[76:], ".text")
	o.PutUint32(b[88:], 0x80001000)
	o.PutUint32(b[92:], 4)
	o.PutUint32(b[96:], 160)
	o.PutUint32(b[100:], 176)
	o.PutUint16(b[108:], 1)
	o.PutUint32(b[112:], 0x20)
	copy(b[116:], ".bss")
	o.PutUint32(b[132:], 8)
	o.PutUint32(b[152:], 0x80)
	copy(b[160:], "code")
	o.PutUint32(b[176:], 0x80001000)
	info := uint32(1<<8 | 4<<1 | 1)
	if o == binary.LittleEndian {
		info = 1 | 4<<27 | 1<<31
	}
	o.PutUint32(b[180:], info)
	o.PutUint32(b[8:], 200)
	o.PutUint32(b[12:], 96)
	h := b[200:296]
	o.PutUint16(h, 0x7009)
	o.PutUint32(h[32:], 1)
	o.PutUint32(h[36:], 320)
	o.PutUint32(h[56:], 4)
	o.PutUint32(h[60:], 500)
	o.PutUint32(h[64:], 9)
	o.PutUint32(h[68:], 520)
	o.PutUint32(h[72:], 1)
	o.PutUint32(h[76:], 336)
	o.PutUint32(h[88:], 1)
	o.PutUint32(h[92:], 432)
	o.PutUint32(b[324:], 0x80001000)
	o.PutUint32(b[332+4+20:], 1)
	o.PutUint32(b[432+8:], 0x80002000)
	copy(b[500:], "foo\x00")
	copy(b[520:], "external\x00")
	return b
}
func TestECOFFSymbolsAndSections(t *testing.T) {
	for _, o := range []binary.ByteOrder{binary.BigEndian, binary.LittleEndian} {
		b := ecoffFixture(o)
		im, err := Open(&starfile.Bytes{Data: b})
		if err != nil {
			t.Fatal(err)
		}
		if im.Entry != 0x80001000 || im.GP != 0x80003000 || im.Sections[1].Data != nil || len(im.Symbols) != 2 || im.Symbols[0].Name != "foo" || im.Symbols[1].Name != "external" {
			t.Fatal(im)
		}
		if r := im.Relocations[0]; r.Types[0] != 4 || !r.External || r.Symbol != 1 {
			t.Fatal(r)
		}
		o.PutUint32(b[200+92:], 633)
		if _, err := Open(&starfile.Bytes{Data: b}); err == nil {
			t.Fatal("accepted truncated external table")
		}
	}
}

func TestELFExtendedHeaderCounts(t *testing.T) {
	for _, class := range []int{32, 64} {
		b := elfFixture(class, binary.BigEndian)
		width, tail := 4, 40
		if class == 64 {
			width, tail = 8, 52
		}
		binary.BigEndian.PutUint16(b[tail+4:], 0xffff)
		binary.BigEndian.PutUint16(b[tail+8:], 0)
		binary.BigEndian.PutUint16(b[tail+10:], 0xffff)
		if class == 64 {
			binary.BigEndian.PutUint64(b[640+8+3*width:], 6)
		} else {
			binary.BigEndian.PutUint32(b[640+8+3*width:], 6)
		}
		binary.BigEndian.PutUint32(b[640+8+4*width:], 5)
		binary.BigEndian.PutUint32(b[640+12+4*width:], 2)
		im, err := Open(&starfile.Bytes{Data: b})
		if err != nil || len(im.Sections) != 6 || len(im.Segments) != 2 || im.Sections[1].Name != ".text" {
			t.Fatal(class, im, err)
		}
	}
}
