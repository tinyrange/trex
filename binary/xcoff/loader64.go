package xcoff

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
)

type LoaderSymbol64 struct {
	Name            string `json:"name"`
	RawNameHex      string `json:"raw_name_hex"`
	Value           uint64 `json:"value"`
	Section         int16  `json:"section"`
	Type            byte   `json:"type"`
	StorageClass    byte   `json:"storage_class"`
	ImportIndex     uint32 `json:"import_index"`
	ParameterOffset uint32 `json:"parameter_offset"`
	EntryDescriptor bool   `json:"entry_descriptor"`
	Imported        bool   `json:"imported"`
	Exported        bool   `json:"exported"`
}
type LoaderRelocation64 struct {
	Address       uint64 `json:"address"`
	SymbolIndex   int32  `json:"symbol_index"`
	Symbol        string `json:"symbol"`
	Type          uint16 `json:"raw_type"`
	Section       uint16 `json:"section"`
	SectionOffset uint64 `json:"section_offset"`
	Bits          uint8  `json:"bits"`
}
type Loader64 struct {
	Symbols     []LoaderSymbol64     `json:"symbols"`
	Imports     []LoaderImport       `json:"imports"`
	Relocations []LoaderRelocation64 `json:"relocations"`
	StringBytes uint32               `json:"string_bytes"`
	Version     uint32               `json:"version"`
}

// ReadLoader decodes the 56-byte XCOFF64 loader tables (observed IBM i
// version 1 and documented version 2) and validates their
// references. It preserves relocation kinds; it does not apply relocations.
func (f *File64) ReadLoader(maximumRecords int, maximumMetadata int64) (*Loader64, error) {
	if maximumRecords < 1 || maximumMetadata < 56 {
		return nil, fmt.Errorf("xcoff loader: invalid record budget")
	}
	var selected *Section64
	for i := range f.sections {
		s := &f.sections[i]
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
	if source == nil || source.Size() < 56 {
		return nil, fmt.Errorf("xcoff loader: missing header")
	}
	var h [56]byte
	if _, err := starfile.ReadFullAt(source, h[:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	version := be.Uint32(h[:])
	ns, nr, il, ni, sl := be.Uint32(h[4:]), be.Uint32(h[8:]), be.Uint32(h[12:]), be.Uint32(h[16:]), be.Uint32(h[20:])
	ip, sp, symp, relp := be.Uint64(h[24:]), be.Uint64(h[32:]), be.Uint64(h[40:]), be.Uint64(h[48:])
	metadata := uint64(56) + uint64(ns)*24 + uint64(nr)*16 + uint64(il) + uint64(sl)
	if (version != 1 && version != 2) || uint64(ns)+uint64(nr)+uint64(ni) > uint64(maximumRecords) || metadata > uint64(maximumMetadata) {
		return nil, fmt.Errorf("xcoff64 loader: version or budget")
	}
	type interval struct{ offset, size uint64 }
	ranges := []interval{{symp, uint64(ns) * 24}, {relp, uint64(nr) * 16}, {ip, uint64(il)}, {sp, uint64(sl)}}
	for i, r := range ranges {
		if r.size == 0 {
			continue
		}
		if r.offset < 56 || !valid64(source, r.offset, r.size) {
			return nil, fmt.Errorf("xcoff64 loader: table bounds")
		}
		for _, prev := range ranges[:i] {
			if prev.size != 0 && r.offset < prev.offset+prev.size && prev.offset < r.offset+r.size {
				return nil, fmt.Errorf("xcoff64 loader: overlapping tables")
			}
		}
	}
	if (ni == 0) != (il == 0) {
		return nil, fmt.Errorf("xcoff64 loader: import size/count")
	}
	records := make([]byte, int(ns)*24+int(nr)*16)
	if ns != 0 {
		if _, err := starfile.ReadFullAt(source, records[:int(ns)*24], int64(symp)); err != nil {
			return nil, err
		}
	}
	if nr != 0 {
		if _, err := starfile.ReadFullAt(source, records[int(ns)*24:], int64(relp)); err != nil {
			return nil, err
		}
	}
	imports := make([]byte, int(il))
	strings := make([]byte, int(sl))
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
	l := &Loader64{Version: version, StringBytes: sl, Symbols: make([]LoaderSymbol64, 0, ns), Imports: make([]LoaderImport, 0, ni), Relocations: make([]LoaderRelocation64, 0, nr)}
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
		offset := be.Uint32(b[8:])
		if offset < 2 || offset >= sl {
			return nil, fmt.Errorf("xcoff64 loader: symbol name offset")
		}
		length := uint32(be.Uint16(strings[offset-2 : offset]))
		if length < 1 || length > sl-offset || strings[offset+length-1] != 0 || bytes.IndexByte(strings[offset:offset+length-1], 0) >= 0 {
			return nil, fmt.Errorf("xcoff64 loader: counted symbol name")
		}
		name := strings[offset : offset+length-1]
		symbol := LoaderSymbol64{Name: escapedName(name), RawNameHex: hex.EncodeToString(name), Value: be.Uint64(b), Section: int16(be.Uint16(b[12:])), Type: b[14], StorageClass: b[15], ImportIndex: be.Uint32(b[16:]), ParameterOffset: be.Uint32(b[20:]), EntryDescriptor: b[14]&0x20 != 0, Imported: b[14]&0x40 != 0, Exported: b[14]&0x10 != 0}
		if symbol.Section < -2 || int(symbol.Section) > len(f.sections) || symbol.ImportIndex >= ni && symbol.ImportIndex != 0 || !symbol.Imported && symbol.ImportIndex != 0 || symbol.ParameterOffset >= sl && symbol.ParameterOffset != 0 {
			return nil, fmt.Errorf("xcoff loader: invalid symbol reference")
		}
		l.Symbols = append(l.Symbols, symbol)
	}
	implicit := map[int32]string{-2: ".tbss", -1: ".tdata", 0: ".text", 1: ".data", 2: ".bss"}
	for i := uint32(0); i < nr; i++ {
		start := int(ns)*24 + int(i)*16
		b := records[start : start+16]
		r := LoaderRelocation64{Address: be.Uint64(b[:]), SymbolIndex: int32(be.Uint32(b[12:])), Type: be.Uint16(b[8:]), Section: be.Uint16(b[10:])}
		r.Bits = uint8((r.Type>>8)&0x3f) + 1
		if r.Section < 1 || int(r.Section) > len(f.sections) || r.Bits > 64 {
			return nil, fmt.Errorf("xcoff loader: relocation section/width")
		}
		s := f.sections[r.Section-1]
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
