// Package xcoff reads bounded XCOFF32/64 headers, sections, and loader tables.
// It does not link, apply relocations, restore memory, or execute objects.
package xcoff

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

type Section struct {
	Name             string         `json:"name"`
	PhysicalAddress  uint32         `json:"physical_address"`
	VirtualAddress   uint32         `json:"virtual_address"`
	Size             uint32         `json:"size"`
	FileOffset       uint32         `json:"file_offset"`
	RelocationOffset uint32         `json:"relocation_offset"`
	LineOffset       uint32         `json:"line_offset"`
	Relocations      uint16         `json:"relocations"`
	Lines            uint16         `json:"lines"`
	Flags            uint32         `json:"flags"`
	Stored           storage.Reader `json:"-"`
}
type File struct {
	Flags            uint16         `json:"flags"`
	SymbolOffset     uint32         `json:"symbol_offset"`
	Symbols          uint32         `json:"symbols"`
	OptionalBytes    uint16         `json:"optional_bytes"`
	OptionalMagic    uint16         `json:"optional_magic"`
	HasEntry         bool           `json:"has_entry"`
	EntryPoint       uint32         `json:"entry_point"`
	TOC              uint32         `json:"toc"`
	Sections         []Section      `json:"sections"`
	DecodingComplete bool           `json:"decoding_complete"`
	RawHeader        storage.Reader `json:"-"`
}

func Open(source storage.Reader, maximumSections int) (*File, error) {
	var h [20]byte
	if source.Size() < 20 || maximumSections < 1 {
		return nil, fmt.Errorf("xcoff: invalid size or budget")
	}
	if _, err := starfile.ReadFullAt(source, h[:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if be.Uint16(h[:]) != 0x01df {
		return nil, fmt.Errorf("xcoff: unsupported generation")
	}
	count := int(be.Uint16(h[2:]))
	f := &File{SymbolOffset: be.Uint32(h[8:]), Symbols: be.Uint32(h[12:]), OptionalBytes: be.Uint16(h[16:]), Flags: be.Uint16(h[18:])}
	sectionStart := int64(20) + int64(f.OptionalBytes)
	headerEnd := sectionStart + int64(count)*40
	if count < 1 || count > maximumSections || headerEnd > source.Size() {
		return nil, fmt.Errorf("xcoff: section headers outside file or budget")
	}
	f.RawHeader = io.NewSectionReader(source, 0, headerEnd)
	valid := func(offset uint32, length uint64) bool {
		return uint64(offset) <= uint64(source.Size()) && length <= uint64(source.Size())-uint64(offset)
	}
	if f.Symbols != 0 && (int64(f.SymbolOffset) < headerEnd || !valid(f.SymbolOffset, uint64(f.Symbols)*18)) {
		return nil, fmt.Errorf("xcoff: symbol table outside file")
	}
	if f.OptionalBytes != 0 {
		if f.OptionalBytes < 28 {
			return nil, fmt.Errorf("xcoff: unsupported short auxiliary header")
		}
		optional := make([]byte, f.OptionalBytes)
		if _, err := starfile.ReadFullAt(source, optional, 20); err != nil {
			return nil, err
		}
		f.OptionalMagic = be.Uint16(optional)
		f.EntryPoint = be.Uint32(optional[16:])
		f.HasEntry = f.EntryPoint != 0xffffffff
		if len(optional) >= 32 {
			f.TOC = be.Uint32(optional[28:])
		}
	}
	for index := 0; index < count; index++ {
		var b [40]byte
		if _, err := starfile.ReadFullAt(source, b[:], sectionStart+int64(index)*40); err != nil {
			return nil, err
		}
		s := Section{Name: strings.TrimRight(string(b[:8]), "\x00"), PhysicalAddress: be.Uint32(b[8:]), VirtualAddress: be.Uint32(b[12:]), Size: be.Uint32(b[16:]), FileOffset: be.Uint32(b[20:]), RelocationOffset: be.Uint32(b[24:]), LineOffset: be.Uint32(b[28:]), Relocations: be.Uint16(b[32:]), Lines: be.Uint16(b[34:]), Flags: be.Uint32(b[36:])}
		if s.Relocations == 0xffff || s.Lines == 0xffff || s.Flags&0xffff == 0x8000 {
			return nil, fmt.Errorf("xcoff: overflow sections require another layout")
		}
		if s.FileOffset != 0 {
			if int64(s.FileOffset) < headerEnd || !valid(s.FileOffset, uint64(s.Size)) {
				return nil, fmt.Errorf("xcoff: section %d outside file", index+1)
			}
			s.Stored = io.NewSectionReader(source, int64(s.FileOffset), int64(s.Size))
		} else if s.Size != 0 && s.Flags&0xffff != 0x80 {
			return nil, fmt.Errorf("xcoff: initialized section without stored contents")
		}
		if s.Relocations != 0 && (int64(s.RelocationOffset) < headerEnd || !valid(s.RelocationOffset, uint64(s.Relocations)*10)) {
			return nil, fmt.Errorf("xcoff: relocation records outside file")
		}
		if s.Lines != 0 && (int64(s.LineOffset) < headerEnd || !valid(s.LineOffset, uint64(s.Lines)*6)) {
			return nil, fmt.Errorf("xcoff: line records outside file")
		}
		f.Sections = append(f.Sections, s)
	}
	return f, nil
}
