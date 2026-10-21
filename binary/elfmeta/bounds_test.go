package elfmeta

import (
	"encoding/binary"
	"testing"
)

func TestDynamicSymbolsAndUnrelatedCompressedDebugSections(t *testing.T) {
	b := fixture(binary.LittleEndian)
	// Dynamic symbols have the same ELF64 layout. Compressed PROGBITS debug
	// data is irrelevant to metadata inspection and must not be inflated.
	binary.LittleEndian.PutUint32(b[0x2c0+4:], 11)
	binary.LittleEndian.PutUint64(b[0x240+8:], 0x800)
	binary.LittleEndian.PutUint64(b[0x240+32:], 32)
	binary.LittleEndian.PutUint32(b[0x100:], 1) // ELF compression header, zlib.
	binary.LittleEndian.PutUint64(b[0x108:], 1<<40)
	binary.LittleEndian.PutUint64(b[0x110:], 1)
	image, err := Open(input(b), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(image.Symbols) != 2 || !image.Symbols[0].Dynamic || !image.Symbols[1].Dynamic || image.Symbols[0].Name != "work" {
		t.Fatal("dynamic projection", image.Symbols)
	}
}

func TestExpandedNameBudgetAndInvalidSectionAreRejected(t *testing.T) {
	for _, modify := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint16(b[0x198+6:], 5) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[0x198+6:], 0xffff) },
	} {
		b := fixture(binary.LittleEndian)
		modify(b)
		if _, err := Open(input(b), Options{}); err == nil {
			t.Fatal("invalid symbol section accepted")
		}
	}
	b := fixture(binary.LittleEndian)
	// The stored string tables fit, but repeated aliases must not expand
	// output names beyond the independently configured byte bound.
	for i := 0x121; i < 0x12b; i++ {
		b[i] = 'x'
	}
	b[0x12b] = 0
	binary.LittleEndian.PutUint32(b[0x198:], 1)
	binary.LittleEndian.PutUint32(b[0x1b0:], 1)
	// Ten-character names repeated at five symbols exceed 45 bytes.
	binary.LittleEndian.PutUint64(b[0x2c0+32:], 144)
	copy(b[0x1c8:0x1e0], b[0x198:0x1b0])
	// Extend table into padding before headers using a separate relocation.
	expanded := make([]byte, len(b)+144)
	copy(expanded, b)
	copy(expanded[0x340:], b[0x180:0x1c8])
	for at := 0x388; at < 0x3d0; at += 24 {
		copy(expanded[at:at+24], b[0x198:0x1b0])
	}
	binary.LittleEndian.PutUint64(expanded[0x2c0+24:], 0x340)
	if _, err := Open(input(expanded), Options{MaximumStringBytes: 45}); err == nil {
		t.Fatal("expanded names exceeded bound")
	}
}
