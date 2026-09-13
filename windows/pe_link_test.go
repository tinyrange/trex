package windows

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"strings"
	"testing"
)

// One cdecl function, its address, and a PC-relative import reference. The
// object is constructed in memory so linker tests need no external compiler.
func linkObjectFixture() []byte {
	out := make([]byte, 356)
	copy(out, "\x7fELF\x01\x01\x01")
	put16 := func(at int, v uint16) { binary.LittleEndian.PutUint16(out[at:], v) }
	put32 := func(at int, v uint32) { binary.LittleEndian.PutUint32(out[at:], v) }
	put16(16, uint16(elf.ET_REL))
	put16(18, uint16(elf.EM_386))
	put32(20, 1)
	put32(32, 52)
	put16(40, 52)
	put16(46, 40)
	put16(48, 5)
	section := func(index int, kind, flags, offset, size, link, info, align, entry uint32) {
		at := 52 + index*40
		for i, value := range []uint32{0, kind, flags, 0, offset, size, link, info, align, entry} {
			put32(at+i*4, value)
		}
	}
	section(1, uint32(elf.SHT_PROGBITS), uint32(elf.SHF_ALLOC|elf.SHF_EXECINSTR), 256, 16, 0, 0, 16, 0)
	section(2, uint32(elf.SHT_SYMTAB), 0, 272, 48, 3, 1, 4, 16)
	section(3, uint32(elf.SHT_STRTAB), 0, 320, 17, 0, 0, 1, 0)
	section(4, uint32(elf.SHT_REL), 0, 340, 16, 2, 1, 4, 8)
	put32(260, 0xfffffffc)
	out[264] = 0xc3
	put32(288, 1)
	put32(292, 8)
	out[300] = 0x12
	put16(302, 1)
	put32(304, 10)
	out[316] = 0x12
	copy(out[320:], "\x00Callback\x00Import\x00")
	put32(340, 0)
	put32(344, 1<<8|uint32(elf.R_386_32))
	put32(348, 4)
	put32(352, 2<<8|uint32(elf.R_386_PC32))
	return out
}

func linkFixtureOptions() PE32LinkOptions {
	return PE32LinkOptions{
		Imports:   map[string]map[string]int{"test.dll": {"Import": 2}},
		Exports:   map[string]int{"Callback": 2},
		Subsystem: 3, VersionMajor: 3, VersionMinor: 10, ImageBase: 0x62000000,
	}
}

func TestPE32LinkRelocationsAndABIBoundaries(t *testing.T) {
	object, options := linkObjectFixture(), linkFixtureOptions()
	out, err := LinkPE32(object, options)
	if err != nil {
		t.Fatal(err)
	}
	again, err := LinkPE32(object, options)
	if err != nil || !bytes.Equal(out, again) {
		t.Fatal("non-deterministic link", err)
	}
	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := f.OptionalHeader.(*pe.OptionalHeader32)
	if h.AddressOfEntryPoint != 0 || h.MajorSubsystemVersion != 3 || h.MinorSubsystemVersion != 10 || f.Characteristics&0x2000 == 0 {
		t.Fatalf("DLL header: %+v", h)
	}
	section, err := f.Sections[0].Data()
	if err != nil {
		t.Fatal(err)
	}
	word := func(at uint32) uint32 { return binary.LittleEndian.Uint32(section[at:]) }
	export := h.DataDirectory[0].VirtualAddress - 0x1000
	functions := word(export+28) - 0x1000
	wrapper := word(functions) - 0x1000
	if word(0) != h.ImageBase+0x1000+wrapper {
		t.Fatal("function address did not select stdcall wrapper")
	}
	if !bytes.Equal(section[wrapper:wrapper+3], []byte{0x55, 0x89, 0xe5}) || !bytes.Equal(section[wrapper+21:wrapper+24], []byte{0xc2, 8, 0}) {
		t.Fatal("stdcall wrapper lacks argument cleanup")
	}
	// The callback wrapper's cdecl call reaches the original object function.
	if int64(wrapper+20)+int64(int32(word(wrapper+16))) != 8 {
		t.Fatal("wrapper does not call the original function")
	}
	importBridge := uint32(int64(8) + int64(int32(word(4))))
	if !bytes.Equal(section[importBridge:importBridge+3], []byte{0x55, 0x89, 0xe5}) || section[importBridge+22] != 0xc3 {
		t.Fatal("import reference did not resolve to cdecl adapter")
	}
	imports, err := f.ImportedSymbols()
	if err != nil || len(imports) != 1 || imports[0] != "Import:test.dll" {
		t.Fatalf("imports %v: %v", imports, err)
	}
	_, checksum, err := peChecksums(out)
	if err != nil || checksum != h.CheckSum {
		t.Fatal("PE checksum", err)
	}
	if h.DataDirectory[5].Size == 0 {
		t.Fatal("absolute addresses lack base relocations")
	}
}

func TestPE32LinkRejectsUnsupportedObjects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte, *PE32LinkOptions)
		want   string
	}{
		{"machine", func(b []byte, _ *PE32LinkOptions) { b[18] = 62 }, "ELF32/i386"},
		{"relocation", func(b []byte, _ *PE32LinkOptions) { b[344] = byte(elf.R_386_GOT32) }, "unsupported i386 relocation"},
		{"target section", func(b []byte, _ *PE32LinkOptions) { binary.LittleEndian.PutUint32(b[240:], 0x10001) }, "invalid relocation target"},
		{"range", func(b []byte, _ *PE32LinkOptions) { binary.LittleEndian.PutUint32(b[340:], 15) }, "outside section"},
		{"symbol", func(b []byte, _ *PE32LinkOptions) { binary.LittleEndian.PutUint32(b[344:], 99<<8|1) }, "symbol table"},
		{"unresolved", func(_ []byte, o *PE32LinkOptions) { o.Imports = nil }, "unresolved symbol"},
		{"callback", func(_ []byte, o *PE32LinkOptions) { o.Callbacks = map[string]int{"Missing": 1} }, "missing callback"},
		{"arity", func(_ []byte, o *PE32LinkOptions) { o.Exports["Callback"] = -1 }, "stack word count"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			object, options := linkObjectFixture(), linkFixtureOptions()
			tc.mutate(object, &options)
			if _, err := LinkPE32(object, options); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
		})
	}
}
