package windows

import (
	"encoding/binary"
	"testing"

	"go.starlark.net/starlark"
)

func coffFixture() []byte {
	data := make([]byte, 160)
	put16 := func(p int, v uint16) { binary.LittleEndian.PutUint16(data[p:], v) }
	put32 := func(p int, v uint32) { binary.LittleEndian.PutUint32(data[p:], v) }
	put16(0, 0x8664)
	put16(2, 1)
	put32(8, 78)
	put32(12, 3)
	copy(data[20:], ".text")
	put32(36, 8)
	put32(40, 60)
	put32(44, 68)
	put16(52, 1)
	copy(data[60:], []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3, 0x90})
	put32(68, 2)
	put32(72, 2)
	put16(76, 4)
	copy(data[78:], ".text")
	put16(90, 1)
	data[94], data[95] = 3, 1 // Static section symbol and one auxiliary record.
	put32(118, 4)             // Long symbol name at string offset four.
	data[130] = 2             // External import symbol.
	put32(132, 28)
	copy(data[136:], "__imp_ExampleKernelCall\x00")
	return data
}

func TestWindowsCOFFSymbolsAndRelocations(t *testing.T) {
	f, err := parseWindowsCOFF(coffFixture())
	if err != nil {
		t.Fatal(err)
	}
	if f.Machine != 0x8664 || len(f.Symbols) != 2 || len(f.COFFSymbols) != 3 || f.Symbols[1].Name != "__imp_ExampleKernelCall" || f.Sections[0].Relocs[0].SymbolTableIndex != 2 {
		t.Fatalf("COFF tables: %+v %+v", f.Symbols, f.Sections)
	}
	value, err := windowsCOFFBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(coffFixture())}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sections, _ := value.(starlark.HasAttrs).Attr("sections")
	section := sections.(*starlark.List).Index(0).(starlark.HasAttrs)
	relocations, _ := section.Attr("relocations")
	symbol, _ := relocations.(*starlark.List).Index(0).(starlark.HasAttrs).Attr("symbol")
	if symbol != starlark.String("__imp_ExampleKernelCall") {
		t.Fatalf("resolved relocation = %s", symbol)
	}
}

func TestWindowsCOFFRejectsMalformedTables(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"header":               func(b []byte) { b[0] = 0; b[1] = 0 },
		"sections":             func(b []byte) { b[3] = 0xff },
		"symbols":              func(b []byte) { b[15] = 0xff },
		"strings":              func(b []byte) { b[135] = 0xff },
		"section-range":        func(b []byte) { b[43] = 0xff },
		"relocation-range":     func(b []byte) { b[47] = 0xff },
		"aux-reference":        func(b []byte) { b[72] = 1 },
		"bad-reference":        func(b []byte) { b[72] = 3 },
		"bad-offset":           func(b []byte) { b[68] = 8 },
		"missing-aux":          func(b []byte) { b[95] = 3 },
		"overflow-relocations": func(b []byte) { b[59] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			data := coffFixture()
			mutate(data)
			if _, err := parseWindowsCOFF(data); err == nil {
				t.Fatal("malformed COFF accepted")
			}
		})
	}
	for n := 0; n < len(coffFixture()); n++ {
		if _, err := parseWindowsCOFF(coffFixture()[:n]); err == nil {
			t.Fatalf("truncated COFF accepted at %d", n)
		}
	}
}

// Small inputs must not amplify repeated table references into unbounded work.
func TestWindowsCOFFBoundsAggregateSections(t *testing.T) {
	data := make([]byte, 20+20*40+65535*10)
	binary.LittleEndian.PutUint16(data, 0x8664)
	binary.LittleEndian.PutUint16(data[2:], 20)
	for i := 0; i < 20; i++ {
		p := 20 + i*40
		binary.LittleEndian.PutUint32(data[p+24:], 820)
		binary.LittleEndian.PutUint16(data[p+32:], 65535)
	}
	if _, err := parseWindowsCOFF(data); err == nil {
		t.Fatal("aggregate relocation amplification accepted")
	}
	for i := 0; i < 20; i++ {
		p := 20 + i*40
		binary.LittleEndian.PutUint16(data[p+32:], 0)
		binary.LittleEndian.PutUint32(data[p+16:], uint32(len(data)-820))
		binary.LittleEndian.PutUint32(data[p+20:], 820)
	}
	if _, err := parseWindowsCOFF(data); err == nil {
		t.Fatal("aggregate section amplification accepted")
	}
}
