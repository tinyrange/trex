package elfmeta

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Independent fixture using ELF64 on-disk offsets, not reader helpers.
func fixture(order binary.ByteOrder) []byte {
	b := make([]byte, 0x340)
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 2, 1, 1
	if order == binary.BigEndian {
		b[5] = 2
	}
	order.PutUint16(b[16:], 2)
	order.PutUint16(b[18:], 62)
	order.PutUint32(b[20:], 1)
	order.PutUint64(b[24:], 0xfedcba9800401000)
	order.PutUint64(b[32:], 64)
	order.PutUint64(b[40:], 0x200)
	order.PutUint16(b[52:], 64)
	order.PutUint16(b[54:], 56)
	order.PutUint16(b[56:], 1)
	order.PutUint16(b[58:], 64)
	order.PutUint16(b[60:], 5)
	order.PutUint16(b[62:], 4)
	order.PutUint32(b[64:], 1)
	order.PutUint32(b[68:], 5)
	order.PutUint64(b[72:], 0x100)
	order.PutUint64(b[80:], 0xfedcba9800401000)
	order.PutUint64(b[96:], 16)
	order.PutUint64(b[104:], 32)
	order.PutUint64(b[112:], 4096)
	copy(b[0x120:], "\x00work\x00alias\x00")
	copy(b[0x140:], "\x00.text\x00.strtab\x00.symtab\x00.shstrtab\x00")
	section := func(index int, name, kind uint32, off, size, entry uint64, link uint32) {
		s := b[0x200+index*64:]
		order.PutUint32(s, name)
		order.PutUint32(s[4:], kind)
		order.PutUint64(s[24:], off)
		order.PutUint64(s[32:], size)
		order.PutUint32(s[40:], link)
		order.PutUint64(s[56:], entry)
	}
	section(1, 1, 1, 0x100, 16, 0, 0)
	section(2, 7, 3, 0x120, 12, 0, 0)
	section(3, 15, 2, 0x180, 72, 24, 2)
	section(4, 23, 3, 0x140, 33, 0, 0)
	s := b[0x198:]
	order.PutUint32(s, 1)
	s[4] = 0x12
	s[5] = 2
	order.PutUint16(s[6:], 1)
	order.PutUint64(s[8:], 0xfedcba9800401000)
	order.PutUint64(s[16:], 8)
	s = b[0x1b0:]
	order.PutUint32(s, 6)
	s[4] = 0x12
	order.PutUint16(s[6:], 1)
	order.PutUint64(s[8:], 0xfedcba9800401008)
	return b
}
func input(b []byte) *starfile.Bytes { return &starfile.Bytes{Name: "elf", Data: b} }

func TestELFSymbolsBothByteOrdersAndZeroSize(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		b := fixture(order)
		image, err := Open(input(b), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if image.Machine != elf.EM_X86_64 || len(image.Symbols) != 2 || image.Entry != 0xfedcba9800401000 || image.LittleEndian != (order == binary.LittleEndian) {
			t.Fatalf("header/symbols: %+v", image)
		}
		s := image.Symbols[0]
		if s.Name != "work" || s.Value != image.Entry || s.Size != 8 || s.Section != 1 || s.Other != 2 || s.Dynamic {
			t.Fatalf("symbol: %+v", s)
		}
		if image.Symbols[1].Size != 0 || image.Symbols[1].Value != image.Entry+8 {
			t.Fatal("zero-size symbol changed")
		}
		if len(image.Segments) != 1 || image.Segments[0].Off != 0x100 || image.Segments[0].Memsz != 32 {
			t.Fatal("load projection")
		}
		// Compare the fixture's symbols independently against the stdlib reader.
		oracle, err := elf.NewFile(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		syms, err := oracle.Symbols()
		if err != nil {
			t.Fatal(err)
		}
		if syms[0] != s.Symbol || syms[1] != image.Symbols[1].Symbol {
			t.Fatal("stdlib oracle mismatch")
		}
	}
}

func TestELFRejectsUntrustedExtentsAndLimits(t *testing.T) {
	put := binary.LittleEndian
	cases := map[string]func([]byte){
		"class":           func(b []byte) { b[4] = 1 },
		"counts":          func(b []byte) { put.PutUint16(b[60:], 5000) },
		"extended":        func(b []byte) { put.PutUint16(b[60:], 0) },
		"headers":         func(b []byte) { put.PutUint64(b[40:], ^uint64(0)-1) },
		"section":         func(b []byte) { put.PutUint64(b[0x240+32:], ^uint64(0)) },
		"name-table-type": func(b []byte) { put.PutUint32(b[0x300+4:], 8) },
		"compressed":      func(b []byte) { put.PutUint64(b[0x300+8:], 0x800) },
		"symbol-count":    func(b []byte) { put.PutUint64(b[0x2c0+32:], 71) },
		"link":            func(b []byte) { put.PutUint32(b[0x2c0+40:], 5) },
		"link-type":       func(b []byte) { put.PutUint32(b[0x2c0+40:], 1) },
		"name-offset":     func(b []byte) { put.PutUint32(b[0x198:], 1000) },
		"name-nul": func(b []byte) {
			for i := 0x126; i < 0x12c; i++ {
				b[i] = 'x'
			}
		},
		"load-file":   func(b []byte) { put.PutUint64(b[96:], ^uint64(0)) },
		"load-memory": func(b []byte) { put.PutUint64(b[104:], ^uint64(0)) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := fixture(put)
			mutate(b)
			if _, err := Open(input(b), Options{}); err == nil {
				t.Fatal("accepted malformed ELF")
			}
		})
	}
	for _, options := range []Options{{MaximumSymbols: 2}, {MaximumStringBytes: 20}, {MaximumSymbols: -1}, {MaximumSymbols: 1000001}} {
		if _, err := Open(input(fixture(put)), options); err == nil {
			t.Fatalf("accepted limits %+v", options)
		}
	}
	for _, n := range []int{0, 1, 63, 64, 100, 0x300} {
		if _, err := Open(input(fixture(put)[:n]), Options{}); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
}

func TestBindingProjectsPortableSymbolMetadata(t *testing.T) {
	value, err := Builtin(nil, nil, starlark.Tuple{input(fixture(binary.LittleEndian))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = starlark.ExecFile(&starlark.Thread{Name: "elf"}, "elf.star", `
def check(ok):
    if not ok:
        fail("ELF projection mismatch")
check(e.machine==62 and e.type==2 and e.little_endian)
check(e.entry==0xfedcba9800401000 and len(e.symbols)==2)
s=e.symbols[0]
check(s.name=="work" and s.address==e.entry and s.size==8)
check(s.type==2 and s.binding==1 and s.visibility==2 and s.section==1 and not s.dynamic)
check(e.symbols[1].size==0)
check(e.segments[0].address==e.entry and e.segments[0].offset==256)
check(e.segments[0].file_size==16 and e.segments[0].memory_size==32 and e.segments[0].flags==5)
`, starlark.StringDict{"e": value})
	if err != nil {
		t.Fatal(err)
	}
}
