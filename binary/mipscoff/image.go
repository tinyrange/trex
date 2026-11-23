// Package mipscoff reads the little-endian MIPS COFF images used by
// the R3000 Jazz ROM loader and early Windows NT.
package mipscoff

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/block"
	"github.com/tinyrange/trex/storage"
)

type Section struct {
	Name                         string
	Address, Size, Offset, Flags uint32
}

func (s Section) ZeroFill() bool { return s.Flags&(0x80|0x400) != 0 }

type Image struct {
	ROM                       bool
	Base, Entry               uint32
	Sections                  []Section
	file                      storage.Reader
	symbolOffset, symbolCount uint32
}

type Symbol struct {
	Name    string
	Address uint32
	Section int16
	Type    uint16
	Class   byte
}

func Open(file storage.Reader) (*Image, error) {
	if file == nil || file.Size() < 76 {
		return nil, fmt.Errorf("MIPS COFF: truncated header")
	}
	var h [76]byte
	if _, err := block.ReadFullAt(file, h[:], 0); err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	optional := int(le.Uint16(h[16:]))
	rom := optional == 56 && le.Uint16(h[20:]) == 0x107
	earlyPE := optional == 160 && le.Uint16(h[20:]) == 0x10b
	if le.Uint16(h[:]) != 0x162 || !rom && !earlyPE {
		return nil, fmt.Errorf("MIPS COFF: expected early R3000 executable")
	}
	sectionTable := 20 + optional
	n := int(le.Uint16(h[2:]))
	if n == 0 || n > 256 || int64(sectionTable+40*n) > file.Size() {
		return nil, fmt.Errorf("MIPS COFF: invalid section count %d", n)
	}
	image := &Image{ROM: rom, Entry: le.Uint32(h[36:]), file: file, symbolOffset: le.Uint32(h[8:]), symbolCount: le.Uint32(h[12:])}
	if earlyPE {
		image.Base = le.Uint32(h[48:])
	}
	var total uint64
	foundEntry := false
	for i := 0; i < n; i++ {
		var sh [40]byte
		if _, err := block.ReadFullAt(file, sh[:], int64(sectionTable+40*i)); err != nil {
			return nil, err
		}
		s := Section{string(bytes.TrimRight(sh[:8], "\x00")), le.Uint32(sh[12:]), le.Uint32(sh[16:]), le.Uint32(sh[20:]), le.Uint32(sh[36:])}
		if s.Size == 0 {
			continue
		}
		end := uint64(s.Address) + uint64(s.Size)
		if end+uint64(image.Base) > 1<<32 || rom && (s.Address < 0x80000000 || end > 0xc0000000 || uint64(s.Address&0x1fffffff)+uint64(s.Size) > 0x20000000) {
			return nil, fmt.Errorf("MIPS COFF: invalid load range for %q", s.Name)
		}
		if !s.ZeroFill() && (s.Offset < uint32(sectionTable+40*n) || uint64(s.Offset)+uint64(s.Size) > uint64(file.Size())) {
			return nil, fmt.Errorf("MIPS COFF: section %q outside file", s.Name)
		}
		mask := uint32(0xffffffff)
		if rom {
			mask = 0x1fffffff
		}
		physical := uint64(s.Address & mask)
		for _, old := range image.Sections {
			oldBase := uint64(old.Address & mask)
			if physical < oldBase+uint64(old.Size) && oldBase < physical+uint64(s.Size) {
				return nil, fmt.Errorf("MIPS COFF: sections %q and %q overlap in physical memory", old.Name, s.Name)
			}
		}
		if !s.ZeroFill() && s.Flags&0x20 != 0 && image.Entry >= s.Address && image.Entry-s.Address < s.Size {
			foundEntry = true
		}
		total += uint64(s.Size)
		if total > 64<<20 {
			return nil, fmt.Errorf("MIPS COFF: loaded sections exceed 64 MiB")
		}
		image.Sections = append(image.Sections, s)
	}
	if (!foundEntry && (rom || image.Entry != 0)) || image.Entry&3 != 0 {
		return nil, fmt.Errorf("MIPS COFF: invalid entry %#x", image.Entry)
	}
	return image, nil
}

func (im *Image) ReadSection(index int, offset uint32, dest []byte) error {
	if index < 0 || index >= len(im.Sections) {
		return fmt.Errorf("MIPS COFF: invalid section index")
	}
	s := im.Sections[index]
	if uint64(offset)+uint64(len(dest)) > uint64(s.Size) {
		return fmt.Errorf("MIPS COFF: read outside section")
	}
	if s.ZeroFill() {
		clear(dest)
		return nil
	}
	_, err := block.ReadFullAt(im.file, dest, int64(s.Offset)+int64(offset))
	return err
}

func (im *Image) Symbols() ([]Symbol, error) {
	if im.symbolOffset == 0 && im.symbolCount == 0 {
		return nil, nil
	}
	off, count := int64(im.symbolOffset), int64(im.symbolCount)
	stringOff := off + count*18
	if off < 76 || count > 1<<20 || stringOff+4 > im.file.Size() {
		return nil, fmt.Errorf("MIPS COFF: invalid symbol table bounds")
	}
	table := make([]byte, count*18)
	if _, err := block.ReadFullAt(im.file, table, off); err != nil {
		return nil, err
	}
	var size [4]byte
	if _, err := block.ReadFullAt(im.file, size[:], stringOff); err != nil {
		return nil, err
	}
	length := int64(binary.LittleEndian.Uint32(size[:]))
	if length < 4 || length > 8<<20 || length > im.file.Size()-stringOff {
		return nil, fmt.Errorf("MIPS COFF: invalid string table bounds")
	}
	names := make([]byte, length)
	if _, err := block.ReadFullAt(im.file, names, stringOff); err != nil {
		return nil, err
	}
	out := make([]Symbol, 0, count)
	le := binary.LittleEndian
	for i := int64(0); i < count; {
		record := table[i*18 : (i+1)*18]
		name := bytes.TrimRight(record[:8], "\x00")
		if le.Uint32(record[:]) == 0 {
			n := le.Uint32(record[4:])
			if n < 4 || int64(n) >= length {
				return nil, fmt.Errorf("MIPS COFF: invalid symbol name offset %d", n)
			}
			end := bytes.IndexByte(names[n:], 0)
			if end < 0 {
				return nil, fmt.Errorf("MIPS COFF: unterminated symbol name")
			}
			name = names[n : uint64(n)+uint64(end)]
		}
		out = append(out, Symbol{string(name), le.Uint32(record[8:]), int16(le.Uint16(record[12:])), le.Uint16(record[14:]), record[16]})
		i += 1 + int64(record[17])
		if i > count {
			return nil, fmt.Errorf("MIPS COFF: truncated auxiliary symbols")
		}
	}
	return out, nil
}
