package macho

import (
	"encoding/binary"
	"testing"
)

func importFixture() source {
	b := make(source, 600)
	u32, u64 := binary.LittleEndian.PutUint32, binary.LittleEndian.PutUint64
	u32(b, 0xfeedfacf)
	u32(b[4:], ARM64)
	u32(b[12:], 2)
	u32(b[16:], 3)
	u32(b[20:], 232+24+80)
	s := b[32:]
	u32(s, 0x19)
	u32(s[4:], 232)
	copy(s[8:], "__TEXT")
	u64(s[24:], 0x100000000)
	u64(s[32:], 600)
	u64(s[48:], 600)
	u32(s[64:], 2)
	stub := s[72:]
	copy(stub, "__stubs")
	u64(stub[32:], 0x100000200)
	u64(stub[40:], 24)
	u32(stub[48:], 512)
	u32(stub[64:], 8)
	u32(stub[72:], 12)
	ptr := s[152:]
	copy(ptr, "__got")
	u64(ptr[32:], 0x100000220)
	u64(ptr[40:], 16)
	u32(ptr[48:], 544)
	u32(ptr[64:], 6)
	u32(ptr[68:], 2)
	sym := b[264:]
	u32(sym, 2)
	u32(sym[4:], 24)
	u32(sym[8:], 400)
	u32(sym[12:], 2)
	u32(sym[16:], 440)
	u32(sym[20:], 14)
	dyn := b[288:]
	u32(dyn, 0xb)
	u32(dyn[4:], 80)
	u32(dyn[56:], 480)
	u32(dyn[60:], 4)
	u32(b[400:], 1)
	b[404] = 1
	u32(b[416:], 8)
	b[420] = 1
	copy(b[440:], "\x00_alpha\x00_beta\x00")
	u32(b[484:], 1)
	u32(b[492:], 0x80000000)
	return b
}

func TestIndirectImportsStubsPointersAndLocalEntries(t *testing.T) {
	i, err := Open(importFixture(), ARM64)
	if err != nil {
		t.Fatal(err)
	}
	if len(i.Imports) != 3 || i.Imports[0] != (Import{"_alpha", "stub", 0x100000200, 12}) || i.Imports[1] != (Import{"_beta", "stub", 0x10000020c, 12}) || i.Imports[2] != (Import{"_alpha", "pointer", 0x100000220, 8}) {
		t.Fatalf("imports=%+v", i.Imports)
	}
}

func TestIndirectImportBounds(t *testing.T) {
	u32, u64 := binary.LittleEndian.PutUint32, binary.LittleEndian.PutUint64
	for name, edit := range map[string]func(source){
		"zero-stub-stride": func(b source) { u32(b[32+72+72:], 0) },
		"partial-stub":     func(b source) { u64(b[32+72+40:], 23) },
		"outside-segment":  func(b source) { u64(b[32+72+32:], 0x100000fff) },
		"outside-indirect": func(b source) { u32(b[32+152+68:], 4) },
		"bad-symbol":       func(b source) { u32(b[480:], 2) },
		"table-outside":    func(b source) { u32(b[288+56:], 599) },
		"table-limit":      func(b source) { u32(b[288+60:], maxSymbols+1) },
	} {
		t.Run(name, func(t *testing.T) {
			b := importFixture()
			edit(b)
			if _, err := Open(b, ARM64); err == nil {
				t.Fatal("accepted malformed indirect imports")
			}
		})
	}
}
