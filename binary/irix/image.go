// Package irix inspects MIPS ELF and ECOFF images as portable, read-only file
// views. It does not load code, apply relocations or emulate an IRIX kernel.
package irix

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"math"
	"strings"
)

const maxRecords = 1 << 20
const maxStrings = 64 << 20

type Section struct {
	Name                                    string
	Type, Link, Info                        uint32
	Flags, Address, Offset, Size, EntrySize uint64
	Data                                    starfile.File
}
type Segment struct {
	Type, Flags                                  uint32
	Address, Offset, Size, MemorySize, Alignment uint64
	Data                                         starfile.File
}
type Symbol struct {
	Name, Table               string
	Value, Size               uint64
	Section                   uint32
	Binding, Type, Visibility byte
}
type Relocation struct {
	Section             string
	Offset              uint64
	Symbol              uint32
	Types               [3]byte
	SpecialSymbol       byte
	Addend              int64
	HasAddend, External bool
	RawInfo             uint64
}
type Dynamic struct {
	Tag   int64
	Value uint64
}
type Image struct {
	Format, Endian, ABI, ISA, Interpreter string
	Class                                 int
	Type                                  uint16
	Flags                                 uint32
	Entry, GP                             uint64
	Sections                              []Section
	Segments                              []Segment
	Symbols                               []Symbol
	Relocations                           []Relocation
	Dynamic                               []Dynamic
	Libraries                             []string
	Options                               []MIPSOption
	ABIFlags                              *ABIFlags
}
type parser struct {
	file        starfile.File
	order       binary.ByteOrder
	used        int
	seenOptions map[[2]uint64]bool
}

func (p *parser) rangeOK(off, size uint64) bool {
	return p.file.Size() >= 0 && off <= uint64(p.file.Size()) && size <= uint64(p.file.Size())-off
}
func (p *parser) read(off, size uint64) ([]byte, error) {
	if size > maxStrings || !p.rangeOK(off, size) {
		return nil, fmt.Errorf("irix executable: invalid or oversized range %#x+%#x", off, size)
	}
	b := make([]byte, size)
	_, err := starfile.ReadFullAt(p.file, b, int64(off))
	return b, err
}
func (p *parser) view(off, size uint64) (starfile.File, error) {
	if !p.rangeOK(off, size) {
		return nil, fmt.Errorf("irix executable: range outside image")
	}
	return &starfile.Slice{Name: "irix executable section", Base: p.file, Offset: int64(off), Length: int64(size)}, nil
}
func (p *parser) budget(n uint64) error {
	if n > maxRecords || uint64(p.used)+n > maxRecords {
		return fmt.Errorf("irix executable: record limit exceeded")
	}
	p.used += int(n)
	return nil
}
func tableString(b []byte, index uint32) (string, error) {
	if uint64(index) >= uint64(len(b)) {
		return "", fmt.Errorf("irix executable: string offset outside table")
	}
	end := strings.IndexByte(string(b[index:]), 0)
	if end < 0 {
		return "", fmt.Errorf("irix executable: unterminated string")
	}
	return string(b[index : int(index)+end]), nil
}
func terminated(b []byte) (string, error) {
	if len(b) == 0 || b[len(b)-1] != 0 {
		return "", fmt.Errorf("irix executable: unterminated interpreter")
	}
	return string(b[:len(b)-1]), nil
}

func Open(file starfile.File) (*Image, error) {
	p := &parser{file: file}
	b, err := p.read(0, 20)
	if err != nil {
		return nil, err
	}
	if string(b[:4]) == "\x7fELF" {
		return p.elf()
	}
	if binary.BigEndian.Uint16(b) == 0x160 || binary.BigEndian.Uint16(b) == 0x163 {
		p.order = binary.BigEndian
		return p.ecoff(b)
	}
	if binary.LittleEndian.Uint16(b) == 0x162 || binary.LittleEndian.Uint16(b) == 0x166 {
		p.order = binary.LittleEndian
		return p.ecoff(b)
	}
	return nil, fmt.Errorf("irix executable: expected MIPS ELF or ECOFF")
}
func (p *parser) elf() (*Image, error) {
	h, err := p.read(0, 16)
	if err != nil {
		return nil, err
	}
	if h[4] != 1 && h[4] != 2 {
		return nil, fmt.Errorf("irix ELF: invalid class")
	}
	if h[5] == 1 {
		p.order = binary.LittleEndian
	} else if h[5] == 2 {
		p.order = binary.BigEndian
	} else {
		return nil, fmt.Errorf("irix ELF: invalid byte order")
	}
	if h[6] != 1 {
		return nil, fmt.Errorf("irix ELF: invalid version")
	}
	width, header, phWidth, shWidth := uint64(4), uint64(52), uint64(32), uint64(40)
	im := &Image{Format: "elf", Class: 32, Endian: "big"}
	if p.order == binary.LittleEndian {
		im.Endian = "little"
	}
	if h[4] == 2 {
		width, header, phWidth, shWidth = 8, 64, 56, 64
		im.Class = 64
	}
	h, err = p.read(0, header)
	if err != nil {
		return nil, err
	}
	o := p.order
	if o.Uint16(h[18:]) != 8 || o.Uint32(h[20:]) != 1 {
		return nil, fmt.Errorf("irix ELF: expected MIPS machine and current version")
	}
	word := func(b []byte) uint64 {
		if width == 4 {
			return uint64(o.Uint32(b))
		}
		return o.Uint64(b)
	}
	im.Type = o.Uint16(h[16:])
	im.Entry = word(h[24:])
	phOff, shOff := word(h[24+width:]), word(h[24+2*width:])
	tail := 24 + 3*width
	im.Flags = o.Uint32(h[tail:])
	tail += 4
	ehSize, phSize, phCount, shSize, shCount, shNames := o.Uint16(h[tail:]), o.Uint16(h[tail+2:]), uint64(o.Uint16(h[tail+4:])), o.Uint16(h[tail+6:]), uint64(o.Uint16(h[tail+8:])), uint64(o.Uint16(h[tail+10:]))
	if uint64(ehSize) != header || (phCount != 0 && uint64(phSize) != phWidth) || (shCount != 0 && uint64(shSize) != shWidth) {
		return nil, fmt.Errorf("irix ELF: invalid header/table entry sizes")
	}
	// Extended counts are stored in the otherwise-null first section.
	if shOff != 0 && (shCount == 0 || phCount == 0xffff || shNames == 0xffff) {
		if uint64(shSize) != shWidth {
			return nil, fmt.Errorf("irix ELF: invalid extended section header size")
		}
		first, err := p.read(shOff, shWidth)
		if err != nil {
			return nil, err
		}
		if shCount == 0 {
			shCount = word(first[8+3*width:])
		}
		if phCount == 0xffff {
			phCount = uint64(o.Uint32(first[8+4*width+4:]))
		}
		if shNames == 0xffff {
			shNames = uint64(o.Uint32(first[8+4*width:]))
		}
	}
	if (shOff == 0 && (shCount != 0 || shNames != 0)) || (phOff == 0 && phCount != 0) {
		return nil, fmt.Errorf("irix ELF: missing header table")
	}
	if err = p.budget(phCount + shCount); err != nil {
		return nil, err
	}
	if !p.rangeOK(phOff, phCount*phWidth) || !p.rangeOK(shOff, shCount*shWidth) {
		return nil, fmt.Errorf("irix ELF: table outside image")
	}
	im.ABI = "o32"
	switch im.Flags & 0xf000 {
	case 0:
		if im.Class == 64 {
			im.ABI = "n64"
		}
	case 0x1000:
		im.ABI = "o32"
	case 0x2000:
		im.ABI = "o64"
	case 0x3000:
		im.ABI = "eabi32"
	case 0x4000:
		im.ABI = "eabi64"
	default:
		return nil, fmt.Errorf("irix ELF: unknown ABI flags")
	}
	if im.Flags&0x20 != 0 {
		if im.Class != 32 || im.Flags&0xf000 != 0 {
			return nil, fmt.Errorf("irix ELF: inconsistent n32 ABI flags")
		}
		im.ABI = "n32"
	}
	if im.Class == 64 && im.ABI == "o32" {
		return nil, fmt.Errorf("irix ELF: inconsistent o32 class")
	}
	isa := []string{"mips1", "mips2", "mips3", "mips4", "mips5", "mips32", "mips64", "mips32r2", "mips64r2", "mips32r6", "mips64r6"}
	arch := im.Flags >> 28
	if arch >= uint32(len(isa)) {
		return nil, fmt.Errorf("irix ELF: unknown ISA flags")
	}
	im.ISA = isa[arch]
	for i := uint64(0); i < phCount; i++ {
		b, err := p.read(phOff+i*phWidth, phWidth)
		if err != nil {
			return nil, err
		}
		s := Segment{Type: o.Uint32(b)}
		if width == 4 {
			s.Offset = word(b[4:])
			s.Address = word(b[8:])
			s.Size = word(b[16:])
			s.MemorySize = word(b[20:])
			s.Flags = o.Uint32(b[24:])
			s.Alignment = word(b[28:])
		} else {
			s.Flags = o.Uint32(b[4:])
			s.Offset = word(b[8:])
			s.Address = word(b[16:])
			s.Size = word(b[32:])
			s.MemorySize = word(b[40:])
			s.Alignment = word(b[48:])
		}
		if s.Type == 1 && (s.Size > s.MemorySize || s.Address > math.MaxUint64-s.MemorySize) {
			return nil, fmt.Errorf("irix ELF: invalid load segment sizes")
		}
		if s.Alignment > 1 && (s.Alignment&(s.Alignment-1) != 0 || (s.Type == 1 && s.Address%s.Alignment != s.Offset%s.Alignment)) {
			return nil, fmt.Errorf("irix ELF: invalid segment alignment")
		}
		s.Data, err = p.view(s.Offset, s.Size)
		if err != nil {
			return nil, err
		}
		im.Segments = append(im.Segments, s)
		if s.Type == 3 {
			b, err := p.read(s.Offset, s.Size)
			if err != nil {
				return nil, err
			}
			im.Interpreter, err = terminated(b)
			if err != nil {
				return nil, err
			}
		}
		if s.Type == 0x70000002 {
			if err := p.mipsOptions(im, s.Offset, s.Size); err != nil {
				return nil, err
			}
		}
		if s.Type == 0x70000003 {
			if err := p.abiFlags(im, s.Offset, s.Size); err != nil {
				return nil, err
			}
		}
		if s.Type == 0x70000000 && s.Size == 24 {
			b, err := p.read(s.Offset, 24)
			if err != nil {
				return nil, err
			}
			im.GP = uint64(o.Uint32(b[20:]))
		}
	}
	for i := uint64(0); i < shCount; i++ {
		b, err := p.read(shOff+i*shWidth, shWidth)
		if err != nil {
			return nil, err
		}
		s := Section{Type: o.Uint32(b[4:]), Flags: word(b[8:]), Address: word(b[8+width:]), Offset: word(b[8+2*width:]), Size: word(b[8+3*width:]), Link: o.Uint32(b[8+4*width:]), Info: o.Uint32(b[12+4*width:]), EntrySize: word(b[16+5*width:])}
		if s.Type != 8 && s.Type != 0 {
			s.Data, err = p.view(s.Offset, s.Size)
			if err != nil {
				return nil, err
			}
		}
		// Name indexes are resolved after the string section is known.
		s.Name = fmt.Sprint(o.Uint32(b))
		im.Sections = append(im.Sections, s)
	}
	if shCount > 0 {
		if shNames >= shCount {
			return nil, fmt.Errorf("irix ELF: section name table index outside table")
		}
		var names []byte
		if shNames != 0 {
			s := im.Sections[shNames]
			if s.Type != 3 {
				return nil, fmt.Errorf("irix ELF: invalid section name table")
			}
			names, err = p.read(s.Offset, s.Size)
			if err != nil {
				return nil, err
			}
		}
		for i := range im.Sections {
			b, readErr := p.read(shOff+uint64(i)*shWidth, 4)
			if readErr != nil {
				return nil, readErr
			}
			index := o.Uint32(b)
			if len(names) == 0 {
				if index != 0 {
					return nil, fmt.Errorf("irix ELF: section names without table")
				}
				im.Sections[i].Name = ""
			} else {
				im.Sections[i].Name, err = tableString(names, index)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	symbolCounts := map[uint32]uint64{}
	for index, s := range im.Sections {
		switch s.Type {
		case 2, 11:
			stride := uint64(16)
			if width == 8 {
				stride = 24
			}
			if s.EntrySize != stride || s.Size%stride != 0 || int(s.Link) >= len(im.Sections) || im.Sections[s.Link].Type != 3 {
				return nil, fmt.Errorf("irix ELF: invalid symbol table")
			}
			count := s.Size / stride
			if err = p.budget(count); err != nil {
				return nil, err
			}
			symbolCounts[uint32(index)] = count
			st := im.Sections[s.Link]
			names, err := p.read(st.Offset, st.Size)
			if err != nil {
				return nil, err
			}
			for i := uint64(0); i < count; i++ {
				b, err := p.read(s.Offset+i*stride, stride)
				if err != nil {
					return nil, err
				}
				name, err := tableString(names, o.Uint32(b))
				if err != nil {
					return nil, err
				}
				sym := Symbol{Name: name, Table: s.Name}
				if width == 4 {
					sym.Value = word(b[4:])
					sym.Size = word(b[8:])
					sym.Binding = b[12] >> 4
					sym.Type = b[12] & 15
					sym.Visibility = b[13] & 3
					sym.Section = uint32(o.Uint16(b[14:]))
				} else {
					sym.Binding = b[4] >> 4
					sym.Type = b[4] & 15
					sym.Visibility = b[5] & 3
					sym.Section = uint32(o.Uint16(b[6:]))
					sym.Value = word(b[8:])
					sym.Size = word(b[16:])
				}
				if sym.Section == 0xffff {
					return nil, fmt.Errorf("irix ELF: extended symbol section indexes unsupported")
				}
				if sym.Section < 0xff00 && uint64(sym.Section) >= shCount {
					return nil, fmt.Errorf("irix ELF: symbol section outside table")
				}
				im.Symbols = append(im.Symbols, sym)
			}
		case 0x7000000d:
			if err := p.mipsOptions(im, s.Offset, s.Size); err != nil {
				return nil, err
			}
		case 0x7000002a:
			if err := p.abiFlags(im, s.Offset, s.Size); err != nil {
				return nil, err
			}
		case 0x70000006:
			if s.Size != 24 {
				return nil, fmt.Errorf("irix ELF: invalid reginfo size")
			}
			b, err := p.read(s.Offset, s.Size)
			if err != nil {
				return nil, err
			}
			im.GP = uint64(o.Uint32(b[20:]))
		}
	}
	for _, s := range im.Sections {
		if s.Type != 4 && s.Type != 9 {
			continue
		}
		stride := width * 2
		if s.Type == 4 {
			stride += width
		}
		symbols, ok := symbolCounts[s.Link]
		if !ok || s.EntrySize != stride || s.Size%stride != 0 || int(s.Info) >= len(im.Sections) {
			return nil, fmt.Errorf("irix ELF: invalid relocation table")
		}
		count := s.Size / stride
		if err = p.budget(count); err != nil {
			return nil, err
		}
		for i := uint64(0); i < count; i++ {
			b, err := p.read(s.Offset+i*stride, stride)
			if err != nil {
				return nil, err
			}
			rel := Relocation{Section: s.Name, Offset: word(b), HasAddend: s.Type == 4, RawInfo: word(b[width:])}
			if width == 4 {
				rel.Symbol = o.Uint32(b[4:]) >> 8
				rel.Types[0] = b[7]
				if p.order == binary.LittleEndian {
					rel.Types[0] = b[4]
				}
			} else {
				rel.Symbol = o.Uint32(b[8:])
				rel.SpecialSymbol = b[12]
				rel.Types = [3]byte{b[15], b[14], b[13]}
			}
			if uint64(rel.Symbol) >= symbols {
				return nil, fmt.Errorf("irix ELF: relocation symbol outside table")
			}
			if rel.HasAddend {
				if width == 4 {
					rel.Addend = int64(int32(o.Uint32(b[8:])))
				} else {
					rel.Addend = int64(o.Uint64(b[16:]))
				}
			}
			im.Relocations = append(im.Relocations, rel)
		}
	}
	// PT_DYNAMIC works on stripped, sectionless IRIX executables too.
	for _, s := range im.Segments {
		if s.Type != 2 {
			continue
		}
		stride := width * 2
		if s.Size%stride != 0 {
			return nil, fmt.Errorf("irix ELF: invalid dynamic segment")
		}
		if err = p.budget(s.Size / stride); err != nil {
			return nil, err
		}
		var stringAddress, stringSize uint64
		var needed []uint32
		ended := false
		for i := uint64(0); i < s.Size/stride; i++ {
			b, err := p.read(s.Offset+i*stride, stride)
			if err != nil {
				return nil, err
			}
			tag := int64(word(b))
			value := word(b[width:])
			if width == 4 {
				tag = int64(int32(tag))
			}
			im.Dynamic = append(im.Dynamic, Dynamic{tag, value})
			if tag == 0 {
				ended = true
				break
			}
			if tag == 5 {
				stringAddress = value
			}
			if tag == 10 {
				stringSize = value
			}
			if tag == 1 {
				if value > math.MaxUint32 {
					return nil, fmt.Errorf("irix ELF: oversized needed string index")
				}
				needed = append(needed, uint32(value))
			}
		}
		if !ended {
			return nil, fmt.Errorf("irix ELF: missing DT_NULL")
		}
		if len(needed) > 0 {
			var table []byte
			for _, load := range im.Segments {
				if load.Type == 1 && stringAddress >= load.Address && stringAddress-load.Address <= load.Size && stringSize <= load.Size-(stringAddress-load.Address) {
					table, err = p.read(load.Offset+stringAddress-load.Address, stringSize)
					if err != nil {
						return nil, err
					}
					break
				}
			}
			if table == nil {
				return nil, fmt.Errorf("irix ELF: unmapped dynamic string table")
			}
			for _, index := range needed {
				name, err := tableString(table, index)
				if err != nil {
					return nil, err
				}
				im.Libraries = append(im.Libraries, name)
			}
		}
	}
	return im, nil
}
func (p *parser) ecoff(h []byte) (*Image, error) {
	o := p.order
	im := &Image{Format: "ecoff", Class: 32, Endian: "big", ABI: "o32", ISA: "mips1", Flags: uint32(o.Uint16(h[18:]))}
	if o == binary.LittleEndian {
		im.Endian = "little"
	}
	if o.Uint16(h) == 0x163 || o.Uint16(h) == 0x166 {
		im.ISA = "mips3"
	}
	n := uint64(o.Uint16(h[2:]))
	optional := uint64(o.Uint16(h[16:]))
	if err := p.budget(n); err != nil {
		return nil, err
	}
	if !p.rangeOK(20+optional, n*40) {
		return nil, fmt.Errorf("irix ECOFF: section table outside image")
	}
	if optional != 0 {
		if optional != 56 {
			return nil, fmt.Errorf("irix ECOFF: unsupported optional header size")
		}
		b, err := p.read(20, 56)
		if err != nil {
			return nil, err
		}
		im.Type = o.Uint16(b)
		if im.Type != 0x107 && im.Type != 0x108 && im.Type != 0x10b {
			return nil, fmt.Errorf("irix ECOFF: invalid executable magic")
		}
		im.Entry = uint64(o.Uint32(b[16:]))
		im.GP = uint64(o.Uint32(b[52:]))
	}
	for i := uint64(0); i < n; i++ {
		b, err := p.read(20+optional+i*40, 40)
		if err != nil {
			return nil, err
		}
		name := strings.TrimRight(string(b[:8]), "\x00")
		s := Section{Name: name, Address: uint64(o.Uint32(b[12:])), Size: uint64(o.Uint32(b[16:])), Offset: uint64(o.Uint32(b[20:])), Flags: uint64(o.Uint32(b[36:]))}
		if s.Size != 0 && s.Flags&(0x80|0x400) == 0 {
			s.Data, err = p.view(s.Offset, s.Size)
			if err != nil {
				return nil, err
			}
		}
		im.Sections = append(im.Sections, s)
		count := uint64(o.Uint16(b[32:]))
		offset := uint64(o.Uint32(b[24:]))
		if err = p.budget(count); err != nil {
			return nil, err
		}
		if !p.rangeOK(offset, count*8) {
			return nil, fmt.Errorf("irix ECOFF: relocation table outside image")
		}
		for j := uint64(0); j < count; j++ {
			r, err := p.read(offset+j*8, 8)
			if err != nil {
				return nil, err
			}
			info := o.Uint32(r[4:])
			rel := Relocation{Section: name, Offset: uint64(o.Uint32(r)), RawInfo: uint64(info)}
			if o == binary.BigEndian {
				rel.Symbol = info >> 8
				rel.Types[0] = byte(info>>1) & 15
				rel.External = info&1 != 0
			} else {
				rel.Symbol = info & 0xffffff
				rel.Types[0] = byte(info>>27) & 15
				rel.External = info&(1<<31) != 0
			}
			im.Relocations = append(im.Relocations, rel)
		}
	}
	// ECOFF's f_nsyms denotes the symbolic header's size, not COFF symbol count.
	symOff := uint64(o.Uint32(h[8:]))
	if symOff != 0 {
		if err := p.ecoffSymbols(im, symOff); err != nil {
			return nil, err
		}
	}
	return im, nil
}
func (p *parser) ecoffSymbols(im *Image, off uint64) error {
	h, err := p.read(off, 96)
	if err != nil {
		return err
	}
	o := p.order
	if o.Uint16(h) != 0x7009 {
		return fmt.Errorf("irix ECOFF: invalid symbolic header")
	}
	localCount, localOff := uint64(o.Uint32(h[32:])), uint64(o.Uint32(h[36:]))
	strSize, strOff := uint64(o.Uint32(h[56:])), uint64(o.Uint32(h[60:]))
	extStrSize, extStrOff := uint64(o.Uint32(h[64:])), uint64(o.Uint32(h[68:]))
	fdCount, fdOff := uint64(o.Uint32(h[72:])), uint64(o.Uint32(h[76:]))
	extCount, extOff := uint64(o.Uint32(h[88:])), uint64(o.Uint32(h[92:]))
	if err = p.budget(localCount + extCount + fdCount); err != nil {
		return err
	}
	locals, err := p.read(strOff, strSize)
	if err != nil {
		return err
	}
	externals, err := p.read(extStrOff, extStrSize)
	if err != nil {
		return err
	}
	if !p.rangeOK(localOff, localCount*12) || !p.rangeOK(extOff, extCount*16) || !p.rangeOK(fdOff, fdCount*72) {
		return fmt.Errorf("irix ECOFF: symbolic table outside image")
	}
	add := func(b, names []byte, base uint32, table string) error {
		index := o.Uint32(b)
		if index > math.MaxUint32-base {
			return fmt.Errorf("irix ECOFF: string index overflow")
		}
		name, err := tableString(names, index+base)
		if err != nil {
			return err
		}
		bits := o.Uint32(b[8:])
		st, sc := byte(bits>>26), byte(bits>>21)&31
		if o == binary.LittleEndian {
			st, sc = byte(bits)&63, byte(bits>>6)&31
		}
		im.Symbols = append(im.Symbols, Symbol{Name: name, Table: table, Value: uint64(o.Uint32(b[4:])), Type: st, Section: uint32(sc)})
		return nil
	}
	used := map[uint64]bool{}
	for i := uint64(0); i < fdCount; i++ {
		fd, err := p.read(fdOff+i*72, 72)
		if err != nil {
			return err
		}
		base := o.Uint32(fd[8:])
		start, count := uint64(o.Uint32(fd[16:])), uint64(o.Uint32(fd[20:]))
		if start > localCount || count > localCount-start {
			return fmt.Errorf("irix ECOFF: file descriptor symbol range")
		}
		for j := start; j < start+count; j++ {
			if used[j] {
				return fmt.Errorf("irix ECOFF: overlapping symbol ownership")
			}
			used[j] = true
			b, err := p.read(localOff+j*12, 12)
			if err != nil {
				return err
			}
			if err = add(b, locals, base, "local"); err != nil {
				return err
			}
		}
	}
	if uint64(len(used)) != localCount {
		return fmt.Errorf("irix ECOFF: local symbols without file descriptor")
	}
	for i := uint64(0); i < extCount; i++ {
		b, err := p.read(extOff+i*16, 16)
		if err != nil {
			return err
		}
		if err = add(b[4:], externals, 0, "external"); err != nil {
			return err
		}
	}
	return nil
}
