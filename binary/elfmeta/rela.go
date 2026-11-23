package elfmeta

import (
	"debug/elf"
	"fmt"
	"io"
)

// Relocation describes one allocated ELF64 dynamic relocation. Address is
// the ELF virtual address for executables and shared objects. Type is specific
// to the ELF machine. Symbol is empty for symbol index zero. RELR entries use
// the original word at Address as their addend.
type Relocation struct {
	Address        uint64
	Type           uint32
	Symbol         string
	Addend         int64
	ImplicitAddend bool
}

func readDynamicRelocations(f *elf.File, symbols []Symbol, maximum int) ([]Relocation, error) {
	const entrySize = 24
	if f.Machine != elf.EM_X86_64 {
		return nil, fmt.Errorf("elf_symbols: dynamic relocations are supported for x86-64 ELF")
	}
	// ELF symbol index zero is the mandatory null entry. Open preserves
	// the order of all subsequent dynamic symbols, including undefined ones.
	names := []string{""}
	for _, symbol := range symbols {
		if symbol.Dynamic {
			names = append(names, symbol.Name)
		}
	}
	var out []Relocation
	for _, section := range f.Sections {
		if section.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		if section.Type == shtRELR {
			var err error
			out, err = readRELR(out, f.ByteOrder, section, maximum)
			if err != nil {
				return nil, err
			}
			continue
		}
		if section.Type != elf.SHT_RELA {
			continue
		}
		if section.Link >= uint32(len(f.Sections)) || f.Sections[section.Link].Type != elf.SHT_DYNSYM {
			return nil, fmt.Errorf("elf_symbols: allocated RELA section %q must link a dynamic symbol table", section.Name)
		}
		if f.Sections[section.Link].Size < 24 {
			return nil, fmt.Errorf("elf_symbols: RELA section %q has no null symbol entry", section.Name)
		}
		if section.Flags&elf.SHF_COMPRESSED != 0 || section.Entsize != entrySize || section.Size%entrySize != 0 || section.Size/entrySize > uint64(maximum-len(out)) {
			return nil, fmt.Errorf("elf_symbols: invalid or over-limit RELA section %q", section.Name)
		}
		source := section.Open()
		var record [entrySize]byte
		for i, count := uint64(0), section.Size/entrySize; i < count; i++ {
			if _, err := io.ReadFull(source, record[:]); err != nil {
				return nil, fmt.Errorf("elf_symbols: read RELA section %q: %w", section.Name, err)
			}
			info := f.ByteOrder.Uint64(record[8:])
			index := info >> 32
			if index >= uint64(len(names)) {
				return nil, fmt.Errorf("elf_symbols: RELA symbol index %d outside dynamic symbol table", index)
			}
			out = append(out, Relocation{
				Address: f.ByteOrder.Uint64(record[:]),
				Type:    uint32(info),
				Symbol:  names[index],
				Addend:  int64(f.ByteOrder.Uint64(record[16:])),
			})
		}
	}
	return out, nil
}
