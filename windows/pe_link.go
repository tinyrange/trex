package windows

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// PE32LinkOptions describes the ABI at a relocatable i386 object's boundary.
// Object functions use cdecl. Named imports, exports and callbacks use stdcall;
// argument counts are 32-bit stack words. No operating-system runtime is linked.
type PE32LinkOptions struct {
	Imports                    map[string]map[string]int // DLL -> symbol -> stack words
	Exports                    map[string]int
	Callbacks                  map[string]int
	Entry                      string // empty for a DLL without an initialization routine
	Subsystem                  uint16
	VersionMajor, VersionMinor uint16
	ImageBase                  uint32
}

// LinkPE32 links one in-memory ELF32/i386 relocatable object into a PE image.
// R_386_32 and R_386_PC32 are supported; other relocation semantics are rejected.
func LinkPE32(object []byte, options PE32LinkOptions) ([]byte, error) {
	if len(object) > 16<<20 {
		return nil, fmt.Errorf("ELF object exceeds link bounds")
	}
	if options.Subsystem != 1 && options.Subsystem != 3 {
		return nil, fmt.Errorf("unsupported PE subsystem")
	}
	for name := range options.Exports {
		if name == "" || strings.ContainsRune(name, 0) {
			return nil, fmt.Errorf("invalid export name")
		}
	}
	f, err := elf.NewFile(bytes.NewReader(object))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if f.Type != elf.ET_REL || f.Class != elf.ELFCLASS32 || f.Machine != elf.EM_386 || f.Data != elf.ELFDATA2LSB {
		return nil, fmt.Errorf("PE32 linking requires a little-endian ELF32/i386 relocatable object")
	}
	if options.ImageBase == 0 {
		options.ImageBase = defaultPE32ImageBase
	}
	if options.ImageBase&0xffff != 0 {
		return nil, fmt.Errorf("PE image base must be 64 KiB aligned")
	}
	if uint64(options.ImageBase)+(32<<20) > 1<<32 {
		return nil, fmt.Errorf("PE image base exceeds link bounds")
	}
	image := &pe32SectionImage{labels: make(map[string]int), imageBase: options.ImageBase}
	offsets, err := image.addELFSections(f)
	if err != nil {
		return nil, err
	}
	symbols, err := image.addELFSymbols(f, offsets)
	if err != nil {
		return nil, err
	}
	callbacks := make(map[string]int)
	for name, words := range options.Callbacks {
		callbacks[name] = words
	}
	for name, words := range options.Exports {
		if count, ok := callbacks[name]; ok && count != words {
			return nil, fmt.Errorf("conflicting ABI for %q", name)
		}
		callbacks[name] = words
	}
	wrappers := make(map[string]int)
	for _, name := range sortedLinkNames(callbacks) {
		if _, ok := image.labels[name]; !ok {
			return nil, fmt.Errorf("missing callback %q", name)
		}
		at, err := image.stdcallBridge(name, callbacks[name], false)
		if err != nil {
			return nil, err
		}
		wrappers[name] = at
	}
	imports := make(map[string][]string)
	importSymbols := make(map[string]int)
	for _, dll := range sortedLinkNames(options.Imports) {
		if dll == "" || strings.ContainsRune(dll, 0) {
			return nil, fmt.Errorf("invalid import DLL")
		}
		for _, name := range sortedLinkNames(options.Imports[dll]) {
			if name == "" || strings.ContainsRune(name, 0) {
				return nil, fmt.Errorf("invalid import name")
			}
			if _, exists := importSymbols[name]; exists {
				return nil, fmt.Errorf("ambiguous import %q", name)
			}
			at, err := image.stdcallBridge("iat:"+dll+":"+name, options.Imports[dll][name], true)
			if err != nil {
				return nil, err
			}
			importSymbols[name] = at
			imports[dll] = append(imports[dll], name)
		}
	}
	if err := image.relocateELF(f, offsets, symbols, wrappers, importSymbols); err != nil {
		return nil, err
	}
	importRVA, importSize, iatRVA, iatSize := image.addImports(imports)
	exportRVA, exportSize := image.addExports(options.Exports, wrappers)
	relocRVA, relocSize := image.addRelocations()
	entry := ""
	if options.Entry != "" {
		at, ok := wrappers[options.Entry]
		if !ok {
			return nil, fmt.Errorf("entry must name an exported stdcall function")
		}
		entry = "pe:entry"
		image.labels[entry] = at
	}
	if err := image.resolve(); err != nil {
		return nil, err
	}
	out := image.peImage(entry, importRVA, importSize, iatRVA, iatSize, relocRVA, relocSize)
	optional := out[0x98:]
	put16 := func(at int, value uint16) { binary.LittleEndian.PutUint16(optional[at:], value) }
	put16(40, options.VersionMajor)
	put16(42, options.VersionMinor)
	put16(48, options.VersionMajor)
	put16(50, options.VersionMinor)
	put16(68, options.Subsystem)
	if entry == "" {
		binary.LittleEndian.PutUint32(optional[16:], 0)
	}
	if options.Subsystem != 1 {
		binary.LittleEndian.PutUint16(out[0x96:], 0x2102)
	}
	binary.LittleEndian.PutUint32(optional[96:], exportRVA)
	binary.LittleEndian.PutUint32(optional[100:], exportSize)
	_, checksum, err := peChecksums(out)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(optional[64:], checksum)
	return out, nil
}

func sortedLinkNames[V any](values map[string]V) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// stdcallBridge emits an ABI adapter, leaving the compiled function untouched.
// Imports are called by cdecl code; exports/callbacks are called by Windows.
func (image *pe32SectionImage) stdcallBridge(target string, words int, imported bool) (int, error) {
	if words < 0 || words > 64 {
		return 0, fmt.Errorf("invalid stack word count for %q", target)
	}
	image.align(16)
	start := len(image.section)
	image.section = append(image.section, 0x55, 0x89, 0xe5) // push ebp; mov ebp,esp
	for word := words - 1; word >= 0; word-- {
		image.section = append(image.section, 0xff, 0xb5) // push [ebp+argument]
		image.dword(uint32(8 + word*4))
	}
	kind := "relative"
	if imported {
		image.section = append(image.section, 0xff, 0x15)
		kind = "address"
	} else {
		image.section = append(image.section, 0xe8)
	}
	image.fixups = append(image.fixups, pe32Fixup{offset: len(image.section), label: target, kind: kind})
	image.dword(0)
	image.section = append(image.section, 0xc9) // leave discards cdecl arguments
	if imported {
		image.section = append(image.section, 0xc3)
	} else {
		image.section = append(image.section, 0xc2, byte(words*4), byte(words*4>>8))
	}
	return start, nil
}

func (image *pe32SectionImage) addExports(exports map[string]int, wrappers map[string]int) (uint32, uint32) {
	if len(exports) == 0 {
		return 0, 0
	}
	image.align(4)
	start := len(image.section)
	image.section = append(image.section, make([]byte, 40)...)
	names := sortedLinkNames(exports)
	functions := len(image.section)
	for _, name := range names {
		image.dword(uint32(0x1000 + wrappers[name]))
	}
	pointers := len(image.section)
	image.section = append(image.section, make([]byte, len(names)*4)...)
	ordinals := len(image.section)
	for i := range names {
		image.section = append(image.section, byte(i), byte(i>>8))
	}
	dll := len(image.section)
	image.section = append(image.section, []byte("trex-driver\x00")...)
	for i, name := range names {
		binary.LittleEndian.PutUint32(image.section[pointers+i*4:], uint32(0x1000+len(image.section)))
		image.section = append(image.section, []byte(name+"\x00")...)
	}
	for offset, value := range map[int]int{12: 0x1000 + dll, 16: 1, 20: len(names), 24: len(names), 28: 0x1000 + functions, 32: 0x1000 + pointers, 36: 0x1000 + ordinals} {
		binary.LittleEndian.PutUint32(image.section[start+offset:], uint32(value))
	}
	return uint32(0x1000 + start), uint32(len(image.section) - start)
}

func (image *pe32SectionImage) addELFSections(f *elf.File) (map[elf.SectionIndex]int, error) {
	offsets := make(map[elf.SectionIndex]int)
	for index, section := range f.Sections {
		if section.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		if section.Flags&(elf.SHF_TLS|elf.SHF_COMPRESSED) != 0 || section.Type != elf.SHT_PROGBITS && section.Type != elf.SHT_NOBITS {
			return nil, fmt.Errorf("unsupported allocated section %q", section.Name)
		}
		alignment := max(section.Addralign, 1)
		if alignment > 4096 || alignment&(alignment-1) != 0 || section.Size > 16<<20 || uint64(len(image.section))+alignment+section.Size > 16<<20 {
			return nil, fmt.Errorf("section %q exceeds link bounds", section.Name)
		}
		image.align(int(alignment))
		offsets[elf.SectionIndex(index)] = len(image.section)
		if section.Type == elf.SHT_NOBITS {
			image.section = append(image.section, make([]byte, int(section.Size))...)
		} else {
			data, err := section.Data()
			if err != nil {
				return nil, err
			}
			image.section = append(image.section, data...)
		}
	}
	return offsets, nil
}

func (image *pe32SectionImage) addELFSymbols(f *elf.File, offsets map[elf.SectionIndex]int) ([]elf.Symbol, error) {
	symbols, err := f.Symbols()
	if err != nil {
		return nil, err
	}
	symbols = append([]elf.Symbol{{}}, symbols...) // ELF relocation indices include STN_UNDEF.
	for _, symbol := range symbols[1:] {
		if at, ok := offsets[symbol.Section]; ok && symbol.Name != "" {
			if symbol.Value > f.Sections[symbol.Section].Size {
				return nil, fmt.Errorf("symbol %q exceeds section", symbol.Name)
			}
			if _, exists := image.labels[symbol.Name]; exists {
				return nil, fmt.Errorf("duplicate symbol %q", symbol.Name)
			}
			image.labels[symbol.Name] = at + int(symbol.Value)
		}
	}
	return symbols, nil
}

func (image *pe32SectionImage) relocateELF(f *elf.File, offsets map[elf.SectionIndex]int, symbols []elf.Symbol, wrappers, importSymbols map[string]int) error {
	for _, section := range f.Sections {
		if section.Type != elf.SHT_REL && section.Type != elf.SHT_RELA {
			continue
		}
		if uint64(section.Info) >= uint64(len(f.Sections)) {
			return fmt.Errorf("invalid relocation target section")
		}
		base, allocated := offsets[elf.SectionIndex(section.Info)]
		if !allocated {
			continue
		}
		if section.Type != elf.SHT_REL || int(section.Link) >= len(f.Sections) || f.Sections[section.Link].Type != elf.SHT_SYMTAB {
			return fmt.Errorf("unsupported relocation section %q", section.Name)
		}
		data, err := section.Data()
		if err != nil {
			return err
		}
		if len(data)%8 != 0 {
			return fmt.Errorf("truncated relocations")
		}
		for at := 0; at < len(data); at += 8 {
			offset := binary.LittleEndian.Uint32(data[at:])
			info := binary.LittleEndian.Uint32(data[at+4:])
			kind, index := elf.R_386(info&255), info>>8
			if kind == elf.R_386_NONE {
				continue
			}
			if kind != elf.R_386_32 && kind != elf.R_386_PC32 {
				return fmt.Errorf("unsupported i386 relocation %s", kind)
			}
			if uint64(offset)+4 > f.Sections[section.Info].Size || index == 0 || int(index) >= len(symbols) {
				return fmt.Errorf("relocation outside section or symbol table")
			}
			symbol := symbols[index]
			target, ok := offsets[symbol.Section]
			if ok {
				if symbol.Value > f.Sections[symbol.Section].Size {
					return fmt.Errorf("symbol exceeds section")
				}
				target += int(symbol.Value)
				// Only addresses crossing the ABI boundary point at stdcall wrappers.
				// Internal PC-relative calls keep their original cdecl targets.
				if wrapper, found := wrappers[symbol.Name]; found && kind == elf.R_386_32 {
					target = wrapper
				}
			} else if symbol.Section == elf.SHN_UNDEF {
				target, ok = importSymbols[symbol.Name]
			}
			if !ok {
				return fmt.Errorf("unresolved symbol %q", symbol.Name)
			}
			where := base + int(offset)
			addend := int(int32(binary.LittleEndian.Uint32(image.section[where:])))
			fixupKind := "address"
			if kind == elf.R_386_PC32 {
				fixupKind = "relative"
				addend += 4
			}
			label := fmt.Sprintf("relocation:%d", where)
			image.labels[label] = target + addend
			image.fixups = append(image.fixups, pe32Fixup{offset: where, label: label, kind: fixupKind})
		}
	}
	return nil
}
