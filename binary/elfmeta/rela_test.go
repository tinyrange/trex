package elfmeta

import (
	"debug/elf"
	"encoding/binary"
	"slices"
	"testing"
)

func relocationFixture() []byte {
	le := binary.LittleEndian
	b := append(fixture(le), make([]byte, 64)...)
	le.PutUint16(b[60:], 6)
	le.PutUint32(b[0x2c4:], uint32(elf.SHT_DYNSYM))
	copy(b[0x161:], ".rela.dyn\x00")
	le.PutUint64(b[0x320:], 43)
	header := b[0x340:]
	le.PutUint32(header, 33)
	le.PutUint32(header[4:], uint32(elf.SHT_RELA))
	le.PutUint64(header[8:], uint64(elf.SHF_ALLOC))
	le.PutUint64(header[24:], 0x1c8)
	le.PutUint64(header[32:], 48)
	le.PutUint32(header[40:], 3)
	le.PutUint64(header[56:], 24)

	le.PutUint64(b[0x1c8:], 0x2200)
	le.PutUint64(b[0x1d0:], 1<<32|uint64(elf.R_X86_64_JMP_SLOT))
	le.PutUint64(b[0x1d8:], ^uint64(3))
	le.PutUint64(b[0x1e0:], 0x2208)
	le.PutUint64(b[0x1e8:], uint64(elf.R_X86_64_RELATIVE))
	le.PutUint64(b[0x1f0:], 0x4321)
	return b
}

func TestAllocatedDynamicRELA(t *testing.T) {
	b := relocationFixture()
	image, err := Open(input(b), Options{})
	if err != nil || len(image.Relocations) != 0 {
		t.Fatalf("relocations should be opt-in: %v", err)
	}
	want := []Relocation{
		{Address: 0x2200, Type: uint32(elf.R_X86_64_JMP_SLOT), Symbol: "work", Addend: -4},
		{Address: 0x2208, Type: uint32(elf.R_X86_64_RELATIVE), Addend: 0x4321},
	}
	image, err = Open(input(b), Options{MaximumRelocations: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(image.Relocations, want) {
		t.Fatalf("relocations = %+v, want %+v", image.Relocations, want)
	}
	if _, err := Open(input(b), Options{MaximumRelocations: 1}); err == nil {
		t.Fatal("accepted over-limit RELA records")
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"partial entry", func(b []byte) { binary.LittleEndian.PutUint64(b[0x360:], 47) }},
		{"bad link", func(b []byte) { binary.LittleEndian.PutUint32(b[0x368:], 1) }},
		{"bad index", func(b []byte) { binary.LittleEndian.PutUint64(b[0x1d0:], 3<<32|7) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := relocationFixture()
			test.mutate(b)
			if _, err := Open(input(b), Options{MaximumRelocations: 2}); err == nil {
				t.Fatal("accepted malformed RELA data")
			}
		})
	}
}

func TestAllocatedDynamicRELR(t *testing.T) {
	b := relocationFixture()
	le := binary.LittleEndian
	copy(b[0x161:], ".relr.dyn\x00")
	section := b[0x340:]
	le.PutUint32(section[4:], uint32(shtRELR))
	le.PutUint64(section[32:], 32)
	le.PutUint32(section[40:], 0)
	le.PutUint64(section[56:], 8)
	for i, entry := range []uint64{0x2000, 1 | 1<<1 | 1<<63, 1 | 1<<2, 0x3000} {
		le.PutUint64(b[0x1c8+i*8:], entry)
	}
	image, err := Open(input(b), Options{MaximumRelocations: 5})
	if err != nil {
		t.Fatal(err)
	}
	want := []Relocation{
		{Address: 0x2000, Type: 8, ImplicitAddend: true},
		{Address: 0x2008, Type: 8, ImplicitAddend: true},
		{Address: 0x21f8, Type: 8, ImplicitAddend: true},
		{Address: 0x2208, Type: 8, ImplicitAddend: true},
		{Address: 0x3000, Type: 8, ImplicitAddend: true},
	}
	if !slices.Equal(image.Relocations, want) {
		t.Fatalf("relocations = %+v, want %+v", image.Relocations, want)
	}
	if _, err := Open(input(b), Options{MaximumRelocations: 4}); err == nil {
		t.Fatal("accepted over-limit RELR records")
	}
	le.PutUint64(b[0x1c8:], 3)
	if _, err := Open(input(b), Options{MaximumRelocations: 5}); err == nil {
		t.Fatal("accepted bitmap before the first address")
	}
}
