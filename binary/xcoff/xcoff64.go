package xcoff

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"strings"
)

type Section64 struct {
	Name             string         `json:"name"`
	PhysicalAddress  uint64         `json:"physical_address"`
	VirtualAddress   uint64         `json:"virtual_address"`
	Size             uint64         `json:"size"`
	FileOffset       uint64         `json:"file_offset"`
	RelocationOffset uint64         `json:"relocation_offset"`
	LineOffset       uint64         `json:"line_offset"`
	Relocations      uint32         `json:"relocations"`
	Lines            uint32         `json:"lines"`
	Flags            uint32         `json:"flags"`
	Stored           storage.Reader `json:"-"`
}
type File64 struct {
	Flags         uint16         `json:"flags"`
	SymbolOffset  uint64         `json:"symbol_offset"`
	Symbols       uint32         `json:"symbols"`
	OptionalBytes uint16         `json:"optional_bytes"`
	OptionalMagic uint16         `json:"optional_magic"`
	HasEntry      bool           `json:"has_entry"`
	EntryPoint    uint64         `json:"entry_point"`
	TOC           uint64         `json:"toc"`
	EntrySection  uint16         `json:"entry_section"`
	TOCSection    uint16         `json:"toc_section"`
	Sections      []Section64    `json:"sections"`
	RawHeader     storage.Reader `json:"-"`
	source        storage.Reader
	sections      []Section64
	symbolOffset  uint64
	symbols       uint32
}

func valid64(source storage.Reader, offset, length uint64) bool {
	return source.Size() >= 0 && offset <= uint64(source.Size()) && length <= uint64(source.Size())-offset
}

// Open64 reads the 24-byte XCOFF64 header and 72-byte section layout. Section
// storage offsets and linked addresses are separate 64-bit domains. BSS has no
// invented contents; neither section nor loader relocations are applied.
func Open64(source storage.Reader, maximumSections int) (*File64, error) {
	var h [24]byte
	if maximumSections < 1 || source.Size() < 24 {
		return nil, fmt.Errorf("xcoff64: invalid size or budget")
	}
	if _, err := starfile.ReadFullAt(source, h[:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if be.Uint16(h[:]) != 0x01f7 {
		return nil, fmt.Errorf("xcoff64: unsupported generation")
	}
	count := int(be.Uint16(h[2:]))
	f := &File64{SymbolOffset: be.Uint64(h[8:]), OptionalBytes: be.Uint16(h[16:]), Flags: be.Uint16(h[18:]), Symbols: be.Uint32(h[20:]), source: source}
	sectionStart := uint64(24) + uint64(f.OptionalBytes)
	end := sectionStart + uint64(count)*72
	if count < 1 || count > maximumSections || !valid64(source, 0, end) {
		return nil, fmt.Errorf("xcoff64: section header bounds")
	}
	f.RawHeader = io.NewSectionReader(source, 0, int64(end))
	f.symbolOffset = f.SymbolOffset
	f.symbols = f.Symbols
	if f.Symbols != 0 && (f.SymbolOffset < end || !valid64(source, f.SymbolOffset, uint64(f.Symbols)*18)) {
		return nil, fmt.Errorf("xcoff64: symbol table bounds")
	}
	if f.OptionalBytes != 0 {
		if f.OptionalBytes < 120 {
			return nil, fmt.Errorf("xcoff64: unsupported short auxiliary header")
		}
		b := make([]byte, f.OptionalBytes)
		if _, err := starfile.ReadFullAt(source, b, 24); err != nil {
			return nil, err
		}
		f.OptionalMagic = be.Uint16(b)
		f.TOC = be.Uint64(b[24:])
		f.EntrySection = be.Uint16(b[32:])
		f.TOCSection = be.Uint16(b[38:])
		f.EntryPoint = be.Uint64(b[80:])
		f.HasEntry = f.EntryPoint != ^uint64(0)
		if int(f.EntrySection) > count || int(f.TOCSection) > count {
			return nil, fmt.Errorf("xcoff64: auxiliary section reference")
		}
	}
	for i := 0; i < count; i++ {
		var b [72]byte
		if _, err := starfile.ReadFullAt(source, b[:], int64(sectionStart)+int64(i)*72); err != nil {
			return nil, err
		}
		s := Section64{Name: strings.TrimRight(string(b[:8]), "\x00"), PhysicalAddress: be.Uint64(b[8:]), VirtualAddress: be.Uint64(b[16:]), Size: be.Uint64(b[24:]), FileOffset: be.Uint64(b[32:]), RelocationOffset: be.Uint64(b[40:]), LineOffset: be.Uint64(b[48:]), Relocations: be.Uint32(b[56:]), Lines: be.Uint32(b[60:]), Flags: be.Uint32(b[64:])}
		if s.Size > ^uint64(0)-s.PhysicalAddress || s.Size > ^uint64(0)-s.VirtualAddress {
			return nil, fmt.Errorf("xcoff64: address overflow")
		}
		if s.FileOffset != 0 {
			if s.FileOffset < end || !valid64(source, s.FileOffset, s.Size) {
				return nil, fmt.Errorf("xcoff64: section storage bounds")
			}
			s.Stored = io.NewSectionReader(source, int64(s.FileOffset), int64(s.Size))
		} else if s.Size != 0 && s.Flags&0xffff != 0x80 && s.Flags&0xffff != 0x800 {
			return nil, fmt.Errorf("xcoff64: initialized section without storage")
		}
		if s.Relocations != 0 && (s.RelocationOffset < end || !valid64(source, s.RelocationOffset, uint64(s.Relocations)*14)) {
			return nil, fmt.Errorf("xcoff64: relocation bounds")
		}
		if s.Lines != 0 && (s.LineOffset < end || !valid64(source, s.LineOffset, uint64(s.Lines)*12)) {
			return nil, fmt.Errorf("xcoff64: line table bounds")
		}
		f.Sections = append(f.Sections, s)
	}
	f.sections = append([]Section64(nil), f.Sections...)
	return f, nil
}

type Symbol64 struct {
	Index        uint32   `json:"index"`
	Name         string   `json:"name"`
	RawNameHex   string   `json:"raw_name_hex"`
	Value        uint64   `json:"value"`
	Section      int16    `json:"section"`
	Type         uint16   `json:"type"`
	StorageClass byte     `json:"storage_class"`
	AuxiliaryHex []string `json:"auxiliary_hex"`
	Csect        *Csect64 `json:"csect,omitempty"`
}
type Csect64 struct {
	LengthOrIndex uint64 `json:"length_or_index"`
	Alignment     uint8  `json:"alignment_log2"`
	Type          uint8  `json:"type"`
	MappingClass  byte   `json:"mapping_class"`
}

// ReadSymbols retains all auxiliary records verbatim. Only AUX_CSECT (251)
// gets a typed view; an unknown auxiliary type is not silently reinterpreted.
func (f *File64) ReadSymbols(maximumRecords int, maximumBytes int64) ([]Symbol64, error) {
	if maximumRecords < 1 || maximumBytes < 0 || uint64(f.symbols) > uint64(maximumRecords) || uint64(f.symbols)*18 > uint64(maximumBytes) {
		return nil, fmt.Errorf("xcoff64 symbols: budget")
	}
	if f.symbols == 0 {
		return []Symbol64{}, nil
	}
	size := uint64(f.symbols) * 18
	start := f.symbolOffset + size
	if !valid64(f.source, start, 4) {
		return nil, fmt.Errorf("xcoff64 symbols: string header")
	}
	var h [4]byte
	if _, err := starfile.ReadFullAt(f.source, h[:], int64(start)); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	sl := uint64(be.Uint32(h[:]))
	if sl < 4 || !valid64(f.source, start, sl) || sl > uint64(maximumBytes)-size {
		return nil, fmt.Errorf("xcoff64 symbols: string bounds or budget")
	}
	table := make([]byte, int(size))
	names := make([]byte, int(sl))
	if _, err := starfile.ReadFullAt(f.source, table, int64(f.symbolOffset)); err != nil {
		return nil, err
	}
	if _, err := starfile.ReadFullAt(f.source, names, int64(start)); err != nil {
		return nil, err
	}
	var debug []byte
	var symbols []Symbol64
	for i := uint32(0); i < f.symbols; {
		b := table[int(i)*18 : int(i+1)*18]
		aux := uint32(b[17])
		offset := be.Uint32(b[8:])
		if aux > f.symbols-i-1 {
			return nil, fmt.Errorf("xcoff64 symbols: auxiliary overrun")
		}
		section := int16(be.Uint16(b[12:]))
		if section < -2 || int(section) > len(f.sections) {
			return nil, fmt.Errorf("xcoff64 symbols: section reference")
		}
		strings := names
		if b[16]&0x80 != 0 {
			if debug == nil {
				var ds storage.Reader
				for _, s := range f.sections {
					if s.Flags&0xffff == 0x2000 {
						if ds != nil {
							return nil, fmt.Errorf("xcoff64 symbols: ambiguous debug section")
						}
						ds = s.Stored
					}
				}
				if ds == nil || uint64(ds.Size()) > uint64(maximumBytes)-size-sl {
					return nil, fmt.Errorf("xcoff64 symbols: debug string bounds or budget")
				}
				debug = make([]byte, int(ds.Size()))
				if _, err := starfile.ReadFullAt(ds, debug, 0); err != nil {
					return nil, err
				}
			}
			strings = debug
		}
		var name []byte
		if offset != 0 {
			if uint64(offset) >= uint64(len(strings)) || (b[16]&0x80 == 0 && offset < 4) {
				return nil, fmt.Errorf("xcoff64 symbols: name offset")
			}
			n := bytes.IndexByte(strings[offset:], 0)
			if n < 0 {
				return nil, fmt.Errorf("xcoff64 symbols: unterminated name")
			}
			name = strings[int(offset) : int(offset)+n]
		}
		symbol := Symbol64{Index: i, Name: escapedName(name), RawNameHex: hex.EncodeToString(name), Value: be.Uint64(b[:]), Section: section, Type: be.Uint16(b[14:]), StorageClass: b[16]}
		for j := uint32(0); j < aux; j++ {
			a := table[int(i+j+1)*18 : int(i+j+2)*18]
			symbol.AuxiliaryHex = append(symbol.AuxiliaryHex, hex.EncodeToString(a))
			if a[17] == 251 {
				if symbol.Csect != nil {
					return nil, fmt.Errorf("xcoff64 symbols: duplicate csect auxiliary")
				}
				symbol.Csect = &Csect64{LengthOrIndex: uint64(be.Uint32(a[12:]))<<32 | uint64(be.Uint32(a[:])), Alignment: a[10] >> 3, Type: a[10] & 7, MappingClass: a[11]}
			}
		}
		symbols = append(symbols, symbol)
		i += 1 + aux
	}
	return symbols, nil
}

type SectionRelocation64 struct {
	Address       uint64 `json:"address"`
	SectionOffset uint64 `json:"section_offset"`
	SymbolIndex   uint32 `json:"symbol_index"`
	Symbol        string `json:"symbol"`
	Bits          uint8  `json:"bits"`
	SizeByte      byte   `json:"size_byte"`
	Type          byte   `json:"type"`
}

func (f *File64) ReadRelocations(section int, maximumRecords int, maximumBytes int64) ([]SectionRelocation64, error) {
	if section < 1 || section > len(f.sections) || maximumRecords < 1 || maximumBytes < 0 {
		return nil, fmt.Errorf("xcoff64 relocations: invalid section/budget")
	}
	s := f.sections[section-1]
	if uint64(s.Relocations) > uint64(maximumRecords) || uint64(s.Relocations)*14 > uint64(maximumBytes) {
		return nil, fmt.Errorf("xcoff64 relocations: record budget")
	}
	if s.Relocations == 0 {
		return []SectionRelocation64{}, nil
	}
	symbols, err := f.ReadSymbols(maximumRecords, maximumBytes-int64(s.Relocations)*14)
	if err != nil {
		return nil, err
	}
	names := make(map[uint32]string, len(symbols))
	for _, symbol := range symbols {
		names[symbol.Index] = symbol.Name
	}
	records := make([]byte, int(s.Relocations)*14)
	if _, err := starfile.ReadFullAt(f.source, records, int64(s.RelocationOffset)); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	out := make([]SectionRelocation64, 0, s.Relocations)
	for i := uint32(0); i < s.Relocations; i++ {
		b := records[int(i)*14 : int(i+1)*14]
		r := SectionRelocation64{Address: be.Uint64(b), SymbolIndex: be.Uint32(b[8:]), SizeByte: b[12], Type: b[13], Bits: (b[12] & 63) + 1}
		name, ok := names[r.SymbolIndex]
		if !ok {
			return nil, fmt.Errorf("xcoff64 relocations: invalid or auxiliary symbol index")
		}
		r.Symbol = name
		if r.Address < s.PhysicalAddress {
			return nil, fmt.Errorf("xcoff64 relocations: address precedes section")
		}
		r.SectionOffset = r.Address - s.PhysicalAddress
		width := (uint64(r.Bits) + 7) / 8
		if r.SectionOffset > s.Size || width > s.Size-r.SectionOffset {
			return nil, fmt.Errorf("xcoff64 relocations: address outside section")
		}
		out = append(out, r)
	}
	return out, nil
}
