package xcoff

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
)

type LoaderSymbol struct {
	Name            string `json:"name"`
	RawNameHex      string `json:"raw_name_hex"`
	Value           uint32 `json:"value"`
	Section         int16  `json:"section"`
	Type            byte   `json:"type"`
	StorageClass    byte   `json:"storage_class"`
	ImportIndex     uint32 `json:"import_index"`
	ParameterOffset uint32 `json:"parameter_offset"`
	EntryDescriptor bool   `json:"entry_descriptor"`
	Imported        bool   `json:"imported"`
	Exported        bool   `json:"exported"`
}
type LoaderImport struct {
	Path   string `json:"path"`
	Base   string `json:"base"`
	Member string `json:"member"`
}
type LoaderRelocation struct {
	Address       uint32 `json:"address"`
	SymbolIndex   int32  `json:"symbol_index"`
	Symbol        string `json:"symbol"`
	Type          uint16 `json:"raw_type"`
	Section       uint16 `json:"section"`
	SectionOffset uint32 `json:"section_offset"`
	Bits          uint8  `json:"bits"`
}
type Loader struct {
	Symbols     []LoaderSymbol     `json:"symbols"`
	Imports     []LoaderImport     `json:"imports"`
	Relocations []LoaderRelocation `json:"relocations"`
	StringBytes uint32             `json:"string_bytes"`
	Version     uint32             `json:"version"`
}

func escapedName(b []byte) string {
	var out []byte
	const digits = "0123456789ABCDEF"
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e && c != '%' {
			out = append(out, c)
		} else {
			out = append(out, '%', digits[c>>4], digits[c&15])
		}
	}
	return string(out)
}

// ReadLoader decodes the version-1 XCOFF32 loader tables and validates their
// references. It preserves relocation kinds; it does not apply relocations.
func (f *File) ReadLoader(maximumRecords int, maximumMetadata int64) (*Loader, error) {
	if maximumRecords < 1 || maximumMetadata < 32 {
		return nil, fmt.Errorf("xcoff loader: invalid record budget")
	}
	var selected *Section
	for i := range f.Sections {
		s := &f.Sections[i]
		if s.Flags&0xffff == 0x1000 {
			if selected != nil {
				return nil, fmt.Errorf("xcoff loader: ambiguous loader section")
			}
			selected = s
		}
	}
	if selected == nil {
		return nil, nil
	}
	source := selected.Stored
	if source == nil || source.Size() < 32 {
		return nil, fmt.Errorf("xcoff loader: missing header")
	}
	var h [32]byte
	if _, err := starfile.ReadFullAt(source, h[:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	version := be.Uint32(h[:])
	ns, nr, il, ni, ip, sl, sp := be.Uint32(h[4:]), be.Uint32(h[8:]), be.Uint32(h[12:]), be.Uint32(h[16:]), be.Uint32(h[20:]), be.Uint32(h[24:]), be.Uint32(h[28:])
	end := uint64(32) + uint64(ns)*24 + uint64(nr)*12
	if version != 1 || uint64(ns)+uint64(nr)+uint64(ni) > uint64(maximumRecords) || end > uint64(source.Size()) || end+uint64(il)+uint64(sl) > uint64(maximumMetadata) {
		return nil, fmt.Errorf("xcoff loader: unsupported version, truncated tables or record budget")
	}
	valid := func(p, n uint32) bool {
		return uint64(p) >= end && uint64(p) <= uint64(source.Size()) && uint64(n) <= uint64(source.Size())-uint64(p)
	}
	if (ni == 0) != (il == 0) || (il != 0 && !valid(ip, il)) || (sl != 0 && !valid(sp, sl)) {
		return nil, fmt.Errorf("xcoff loader: strings outside section")
	}
	if il != 0 && sl != 0 && uint64(ip) < uint64(sp)+uint64(sl) && uint64(sp) < uint64(ip)+uint64(il) {
		return nil, fmt.Errorf("xcoff loader: overlapping string tables")
	}
	records := make([]byte, int(end)-32)
	if _, err := starfile.ReadFullAt(source, records, 32); err != nil {
		return nil, err
	}
	imports := make([]byte, il)
	strings := make([]byte, sl)
	if il != 0 {
		if _, err := starfile.ReadFullAt(source, imports, int64(ip)); err != nil {
			return nil, err
		}
	}
	if sl != 0 {
		if _, err := starfile.ReadFullAt(source, strings, int64(sp)); err != nil {
			return nil, err
		}
	}
	l := &Loader{Version: version, StringBytes: sl, Symbols: make([]LoaderSymbol, 0, ns), Imports: make([]LoaderImport, 0, ni), Relocations: make([]LoaderRelocation, 0, nr)}
	cursor := 0
	for i := uint32(0); i < ni; i++ {
		var words [3]string
		for j := range words {
			if cursor >= len(imports) {
				return nil, fmt.Errorf("xcoff loader: short import descriptor")
			}
			n := bytes.IndexByte(imports[cursor:], 0)
			if n < 0 {
				return nil, fmt.Errorf("xcoff loader: unterminated import")
			}
			words[j] = escapedName(imports[cursor : cursor+n])
			cursor += n + 1
		}
		l.Imports = append(l.Imports, LoaderImport{Path: words[0], Base: words[1], Member: words[2]})
	}
	if cursor != len(imports) {
		return nil, fmt.Errorf("xcoff loader: trailing import bytes")
	}
	for i := uint32(0); i < ns; i++ {
		b := records[int(i)*24 : int(i)*24+24]
		name := bytes.TrimRight(b[:8], "\x00")
		if be.Uint32(b[:4]) == 0 {
			offset := be.Uint32(b[4:])
			if offset < 2 || offset >= sl {
				return nil, fmt.Errorf("xcoff loader: symbol name offset")
			}
			length := uint32(be.Uint16(strings[offset-2 : offset]))
			if length < 1 || length > sl-offset || strings[offset+length-1] != 0 || bytes.IndexByte(strings[offset:offset+length-1], 0) >= 0 {
				return nil, fmt.Errorf("xcoff loader: counted symbol name")
			}
			name = strings[offset : offset+length-1]
		}
		symbol := LoaderSymbol{Name: escapedName(name), RawNameHex: hex.EncodeToString(name), Value: be.Uint32(b[8:]), Section: int16(be.Uint16(b[12:])), Type: b[14], StorageClass: b[15], ImportIndex: be.Uint32(b[16:]), ParameterOffset: be.Uint32(b[20:]), EntryDescriptor: b[14]&0x20 != 0, Imported: b[14]&0x40 != 0, Exported: b[14]&0x10 != 0}
		if symbol.Section < -2 || int(symbol.Section) > len(f.Sections) || symbol.ImportIndex >= ni && symbol.ImportIndex != 0 || !symbol.Imported && symbol.ImportIndex != 0 || symbol.ParameterOffset >= sl && symbol.ParameterOffset != 0 {
			return nil, fmt.Errorf("xcoff loader: invalid symbol reference")
		}
		l.Symbols = append(l.Symbols, symbol)
	}
	implicit := map[int32]string{-2: ".tbss", -1: ".tdata", 0: ".text", 1: ".data", 2: ".bss"}
	for i := uint32(0); i < nr; i++ {
		start := int(ns)*24 + int(i)*12
		b := records[start : start+12]
		r := LoaderRelocation{Address: be.Uint32(b[:]), SymbolIndex: int32(be.Uint32(b[4:])), Type: be.Uint16(b[8:]), Section: be.Uint16(b[10:])}
		r.Bits = uint8((r.Type>>8)&0x3f) + 1
		if r.Section < 1 || int(r.Section) > len(f.Sections) || r.Bits > 32 {
			return nil, fmt.Errorf("xcoff loader: relocation section/width")
		}
		s := f.Sections[r.Section-1]
		if r.Address < s.PhysicalAddress {
			return nil, fmt.Errorf("xcoff loader: relocation address precedes section")
		}
		r.SectionOffset = r.Address - s.PhysicalAddress
		width := (uint64(r.Bits) + 7) / 8
		if uint64(r.SectionOffset) > uint64(s.Size) || width > uint64(s.Size)-uint64(r.SectionOffset) {
			return nil, fmt.Errorf("xcoff loader: relocation outside section")
		}
		if name, ok := implicit[r.SymbolIndex]; ok {
			r.Symbol = name
		} else {
			if r.SymbolIndex < 3 || uint64(r.SymbolIndex-3) >= uint64(len(l.Symbols)) {
				return nil, fmt.Errorf("xcoff loader: relocation symbol index")
			}
			r.Symbol = l.Symbols[r.SymbolIndex-3].Name
		}
		l.Relocations = append(l.Relocations, r)
	}
	return l, nil
}
