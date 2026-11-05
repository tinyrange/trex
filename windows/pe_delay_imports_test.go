package windows

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func delayImportFixture(is64, legacy bool) []byte {
	b := make([]byte, 0x800)
	put16 := func(at int, v uint16) { binary.LittleEndian.PutUint16(b[at:], v) }
	put32 := func(at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
	copy(b, "MZ")
	put32(0x3c, 0x80)
	copy(b[0x80:], "PE\x00\x00")
	optional, directories := 224, 0x98+96
	put16(0x84, 0x14c)
	put16(0x98, 0x10b)
	put32(0x98+28, 0x400000)
	put32(0x98+92, 16)
	if is64 {
		optional, directories = 240, 0x98+112
		put16(0x84, 0x8664)
		put16(0x98, 0x20b)
		binary.LittleEndian.PutUint64(b[0x98+24:], 0x180000000)
		put32(0x98+108, 16)
	}
	put16(0x86, 1)
	put16(0x94, uint16(optional))
	put32(0x98+32, 0x1000)
	put32(0x98+36, 0x200)
	put32(0x98+56, 0x2000)
	put32(0x98+60, 0x200)
	put32(directories+13*8, 0x1000)
	put32(directories+13*8+4, 64)
	section := 0x98 + optional
	copy(b[section:], ".rdata")
	put32(section+8, 0x1000) // Deliberate virtual-only tail after raw bytes.
	put32(section+12, 0x1000)
	put32(section+16, 0x600)
	put32(section+20, 0x200)
	put32(section+36, 0x40000040)
	address := func(rva uint32) uint32 {
		if legacy {
			return 0x400000 + rva
		}
		return rva
	}
	if !legacy {
		put32(0x200, 1)
	}
	put32(0x204, address(0x1100))
	put32(0x208, address(0x1130))
	put32(0x20c, address(0x1140))
	put32(0x210, address(0x1180))
	copy(b[0x300:], "provider.dll\x00")
	if is64 {
		binary.LittleEndian.PutUint64(b[0x380:], 0x11c0)
		binary.LittleEndian.PutUint64(b[0x388:], 1<<63|9)
	} else {
		put32(0x380, address(0x11c0))
		put32(0x384, 1<<31|9)
	}
	put16(0x3c0, 7)
	copy(b[0x3c2:], "RegisterExample\x00")
	return b
}

func TestPEDelayImports(t *testing.T) {
	for _, tc := range []struct {
		name         string
		is64, legacy bool
	}{{"PE32 RVA", false, false}, {"PE32 VA", false, true}, {"PE32+ RVA", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			b := delayImportFixture(tc.is64, tc.legacy)
			imports, err := peDelayImports(b)
			if err != nil {
				t.Fatal(err)
			}
			width := uint32(4)
			if tc.is64 {
				width = 8
			}
			if len(imports) != 2 || imports[0].dll != "provider.dll" || imports[0].name != "RegisterExample" || imports[0].hint != 7 || imports[0].tableRVA != 0x1180 || imports[0].iatRVA != 0x1140 || imports[1].ordinal != 9 || imports[1].iatRVA != 0x1140+width {
				t.Fatalf("unexpected delayed imports: %#v", imports)
			}
			ordinary, err := peImports(b)
			if err != nil || len(ordinary) != 0 {
				t.Fatalf("ordinary imports changed: %v %v", ordinary, err)
			}
			object := &windowsPE{file: &starfile.Bytes{Data: b}, cache: make(starlark.StringDict)}
			value, err := object.Attr("delay_imports")
			if err != nil || value.(*starlark.List).Len() != 2 {
				t.Fatalf("property: %v %v", value, err)
			}
			if err := value.(*starlark.List).Append(starlark.None); err == nil {
				t.Fatal("cached import list is mutable")
			}
		})
	}
}

func TestPEDelayImportsRejectMalformed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"reserved attributes", func(b []byte) { b[0x200] = 3 }},
		{"missing terminator", func(b []byte) { binary.LittleEndian.PutUint32(b[0x98+96+13*8+4:], 32) }},
		{"truncated descriptor", func(b []byte) { binary.LittleEndian.PutUint32(b[0x98+96+13*8+4:], 31) }},
		{"virtual-only name", func(b []byte) { binary.LittleEndian.PutUint32(b[0x204:], 0x1700) }},
		{"virtual-only IAT", func(b []byte) { binary.LittleEndian.PutUint32(b[0x20c:], 0x1700) }},
		{"virtual-only INT", func(b []byte) { binary.LittleEndian.PutUint32(b[0x210:], 0x1700) }},
		{"unterminated name", func(b []byte) { binary.LittleEndian.PutUint32(b[0x204:], 0x15ff); b[0x7ff] = 'x' }},
		{"VA below image", func(b []byte) { b[0x200] = 0 }},
		{"reserved ordinal bits", func(b []byte) { binary.LittleEndian.PutUint32(b[0x384:], 0x80010009) }},
		{"unterminated thunks", func(b []byte) {
			binary.LittleEndian.PutUint32(b[0x210:], 0x15fc)
			binary.LittleEndian.PutUint32(b[0x7fc:], 0x80000009)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := delayImportFixture(false, false)
			tc.mutate(b)
			if _, err := peDelayImports(b); err == nil {
				t.Fatal("accepted malformed delay imports")
			}
		})
	}
	b := delayImportFixture(true, false)
	binary.LittleEndian.PutUint64(b[0x380:], 0x1000011c0)
	if _, err := peDelayImports(b); err == nil {
		t.Fatal("accepted overflowing PE32+ name RVA")
	}
}

func TestPEDelayImportsAbsentAndOrdinalZero(t *testing.T) {
	b := delayImportFixture(false, false)
	binary.LittleEndian.PutUint32(b[0x98+96+13*8:], 0)
	binary.LittleEndian.PutUint32(b[0x98+96+13*8+4:], 0)
	if imports, err := peDelayImports(b); err != nil || len(imports) != 0 {
		t.Fatalf("absent directory: %v %v", imports, err)
	}
	b = delayImportFixture(false, false)
	binary.LittleEndian.PutUint32(b[0x384:], 1<<31)
	imports, err := peDelayImports(b)
	if err != nil {
		t.Fatal(err)
	}
	value, err := peImportsValue(imports)
	if err != nil {
		t.Fatal(err)
	}
	ordinal, found, err := value.(*starlark.List).Index(1).(*starlark.Dict).Get(starlark.String("ordinal"))
	if err != nil || !found || ordinal.String() != "0" {
		t.Fatalf("ordinal zero was lost: %v %v %v", ordinal, found, err)
	}
}
