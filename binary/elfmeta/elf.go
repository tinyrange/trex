// Package elfmeta reads bounded ELF64 symbols and load segments from portable
// random-access files. It never loads code or resolves symbols on the host.
package elfmeta

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

type Options struct{ MaximumSymbols, MaximumStringBytes int }
type Image struct {
	Type         elf.Type
	Machine      elf.Machine
	Entry        uint64
	LittleEndian bool
	Symbols      []Symbol
	Segments     []elf.ProgHeader
}
type Symbol struct {
	elf.Symbol
	Dynamic bool
}

func Open(r storage.Reader, options Options) (*Image, error) {
	if options.MaximumSymbols == 0 {
		options.MaximumSymbols = 1000000
	}
	if options.MaximumStringBytes == 0 {
		options.MaximumStringBytes = 16 << 20
	}
	if options.MaximumSymbols < 1 || options.MaximumSymbols > 1000000 || options.MaximumStringBytes < 1 || options.MaximumStringBytes > 64<<20 {
		return nil, fmt.Errorf("elf_symbols: invalid resource limits")
	}
	if r == nil || r.Size() < 64 {
		return nil, fmt.Errorf("elf_symbols: short ELF64 header")
	}
	size := uint64(r.Size())
	within := func(off, n uint64) bool { return off <= size && n <= size-off }
	read := func(off uint64, b []byte) error {
		if !within(off, uint64(len(b))) {
			return fmt.Errorf("elf_symbols: extent outside file")
		}
		n, err := r.ReadAt(b, int64(off))
		if n != len(b) {
			return fmt.Errorf("elf_symbols: short read at %#x", off)
		}
		if err != nil && err != io.EOF {
			return err
		}
		return nil
	}
	var h [64]byte
	if err := read(0, h[:]); err != nil {
		return nil, err
	}
	if string(h[:4]) != "\x7fELF" || h[4] != 2 || h[6] != 1 {
		return nil, fmt.Errorf("elf_symbols: expected ELF64 version 1")
	}
	var order binary.ByteOrder
	switch h[5] {
	case 1:
		order = binary.LittleEndian
	case 2:
		order = binary.BigEndian
	default:
		return nil, fmt.Errorf("elf_symbols: unsupported byte order")
	}
	if order.Uint32(h[20:]) != 1 || order.Uint16(h[52:]) != 64 {
		return nil, fmt.Errorf("elf_symbols: invalid ELF header")
	}
	phoff, shoff := order.Uint64(h[32:]), order.Uint64(h[40:])
	phentsize, phnum := uint64(order.Uint16(h[54:])), uint64(order.Uint16(h[56:]))
	shentsize, shnum := uint64(order.Uint16(h[58:])), uint64(order.Uint16(h[60:]))
	shstr := uint64(order.Uint16(h[62:]))
	// Reject extended numbering explicitly; bound counts BEFORE debug/elf can
	// allocate tables or read its section-name string table.
	if phnum > 4096 || shnum > 4096 || shstr == 0xffff || (shnum == 0 && shoff != 0) || (shnum != 0 && shstr >= shnum) {
		return nil, fmt.Errorf("elf_symbols: extended or over-limit header tables")
	}
	if (phnum != 0 && (phentsize != 56 || !within(phoff, phnum*56))) || (shnum != 0 && (shentsize != 64 || !within(shoff, shnum*64))) {
		return nil, fmt.Errorf("elf_symbols: invalid header table extent")
	}
	strings, symbols := uint64(0), uint64(0)
	tables := map[uint32]bool{}
	parsed := []Symbol{}
	nameBudget := options.MaximumStringBytes
	for i := uint64(0); i < shnum; i++ {
		var b [64]byte
		if err := read(shoff+i*64, b[:]); err != nil {
			return nil, err
		}
		kind, flags, off, n, entry := order.Uint32(b[4:]), order.Uint64(b[8:]), order.Uint64(b[24:]), order.Uint64(b[32:]), order.Uint64(b[56:])
		if flags&0x800 != 0 && (kind == uint32(elf.SHT_STRTAB) || kind == uint32(elf.SHT_SYMTAB) || kind == uint32(elf.SHT_DYNSYM)) {
			return nil, fmt.Errorf("elf_symbols: compressed symbol/string metadata unsupported")
		}
		if kind != uint32(elf.SHT_NOBITS) && !within(off, n) {
			return nil, fmt.Errorf("elf_symbols: section outside file")
		}
		if i == shstr && shstr != 0 && kind != uint32(elf.SHT_STRTAB) {
			return nil, fmt.Errorf("elf_symbols: section names are not a string table")
		}
		if kind == uint32(elf.SHT_STRTAB) {
			if n > uint64(options.MaximumStringBytes)-strings {
				return nil, fmt.Errorf("elf_symbols: string table limit")
			}
			strings += n
		}
		if kind == uint32(elf.SHT_SYMTAB) || kind == uint32(elf.SHT_DYNSYM) {
			if tables[kind] || entry != 24 || n%24 != 0 || n/24 > uint64(options.MaximumSymbols)-symbols {
				return nil, fmt.Errorf("elf_symbols: invalid or over-limit symbol table")
			}
			tables[kind] = true
			symbols += n / 24
			link := uint64(order.Uint32(b[40:]))
			if link >= shnum {
				return nil, fmt.Errorf("elf_symbols: symbol string-table link outside sections")
			}
			var linked [64]byte
			if err := read(shoff+link*64, linked[:]); err != nil {
				return nil, err
			}
			if order.Uint32(linked[4:]) != uint32(elf.SHT_STRTAB) {
				return nil, fmt.Errorf("elf_symbols: symbol link is not a string table")
			}
			stringOff, stringSize := order.Uint64(linked[24:]), order.Uint64(linked[32:])
			if stringSize > uint64(options.MaximumStringBytes) || !within(stringOff, stringSize) {
				return nil, fmt.Errorf("elf_symbols: invalid symbol string extent")
			}
			names := make([]byte, int(stringSize))
			if err := read(stringOff, names); err != nil {
				return nil, err
			}
			for j := uint64(0); j < n/24; j++ {
				var symbol [24]byte
				if err := read(off+j*24, symbol[:]); err != nil {
					return nil, err
				}
				name := uint64(order.Uint32(symbol[:]))
				if name >= stringSize {
					return nil, fmt.Errorf("elf_symbols: invalid symbol name offset")
				}
				end := stringSize
				if uint64(nameBudget)+1 < end-name {
					end = name + uint64(nameBudget) + 1
				}
				length := bytes.IndexByte(names[name:end], 0)
				if length < 0 || length > nameBudget {
					return nil, fmt.Errorf("elf_symbols: unterminated or over-limit symbol name")
				}
				nameBudget -= length
				section := elf.SectionIndex(order.Uint16(symbol[6:]))
				if section == elf.SHN_XINDEX || (section < elf.SHN_LORESERVE && uint64(section) >= shnum) {
					return nil, fmt.Errorf("elf_symbols: invalid or extended symbol section")
				}
				if j != 0 {
					parsed = append(parsed, Symbol{Symbol: elf.Symbol{Name: string(names[name : name+uint64(length)]), Info: symbol[4], Other: symbol[5], Section: section, Value: order.Uint64(symbol[8:]), Size: order.Uint64(symbol[16:])}, Dynamic: kind == uint32(elf.SHT_DYNSYM)})
				}
			}
		}
	}
	f, err := elf.NewFile(io.NewSectionReader(r, 0, r.Size()))
	if err != nil {
		return nil, fmt.Errorf("elf_symbols: %w", err)
	}
	defer f.Close()
	out := &Image{Type: f.Type, Machine: f.Machine, Entry: f.Entry, LittleEndian: h[5] == 1}
	out.Symbols = parsed
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if !within(p.Off, p.Filesz) || p.Filesz > p.Memsz || p.Memsz > ^uint64(0)-p.Vaddr {
			return nil, fmt.Errorf("elf_symbols: invalid load segment")
		}
		out.Segments = append(out.Segments, p.ProgHeader)
	}
	return out, nil
}
