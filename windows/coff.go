package windows

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"

	starvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
)

// parseWindowsCOFF bounds all allocation-driving tables before invoking the
// standard COFF reader. Symbol indices retain auxiliary records so relocations
// can be related to their original symbol-table entries.
func parseWindowsCOFF(data []byte) (*pe.File, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("truncated COFF header")
	}
	u16 := func(p int) uint16 { return binary.LittleEndian.Uint16(data[p:]) }
	u32 := func(p int) uint64 { return uint64(binary.LittleEndian.Uint32(data[p:])) }
	if u16(0) == 0 || u16(0) == 0x5a4d || u16(16) != 0 {
		return nil, fmt.Errorf("expected standard COFF object (no optional header)")
	}
	within := func(p, n uint64) bool { return p <= uint64(len(data)) && n <= uint64(len(data))-p }
	sections := uint64(u16(2))
	if sections > 4096 || !within(20, sections*40) {
		return nil, fmt.Errorf("invalid COFF section table")
	}
	symbols, symbolOffset := u32(12), u32(8)
	if symbols > 1<<20 || (symbols != 0 && symbolOffset == 0) || !within(symbolOffset, symbols*18) {
		return nil, fmt.Errorf("invalid COFF symbol table")
	}
	if symbolOffset != 0 {
		strings := symbolOffset + symbols*18
		if !within(strings, 4) || u32(int(strings)) < 4 || !within(strings, u32(int(strings))) {
			return nil, fmt.Errorf("invalid COFF string table")
		}
	}
	var backedBytes, relocationCount uint64
	for i := uint64(0); i < sections; i++ {
		p := int(20 + i*40)
		if u32(p+20) != 0 {
			backedBytes += u32(p + 16)
		}
		relocationCount += uint64(u16(p + 32))
		if backedBytes > uint64(len(data)) || relocationCount > 1<<20 {
			return nil, fmt.Errorf("COFF aggregate section data or relocations exceed limits")
		}
		if u32(p+36)&0x1000000 != 0 {
			return nil, fmt.Errorf("COFF relocation overflow tables are not supported")
		}
		if (u32(p+20) != 0 && !within(u32(p+20), u32(p+16))) || !within(u32(p+24), uint64(u16(p+32))*10) || !within(u32(p+28), uint64(u16(p+34))*6) {
			return nil, fmt.Errorf("COFF section %d exceeds input", i+1)
		}
	}
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	primary := make(map[uint32]bool)
	for i := 0; i < len(f.COFFSymbols); {
		s := f.COFFSymbols[i]
		if s.SectionNumber > int16(sections) {
			return nil, fmt.Errorf("COFF symbol %d has invalid section", i)
		}
		primary[uint32(i)] = true
		i += 1 + int(s.NumberOfAuxSymbols)
	}
	for _, section := range f.Sections {
		for _, relocation := range section.Relocs {
			if !primary[relocation.SymbolTableIndex] || relocation.VirtualAddress >= section.Size {
				return nil, fmt.Errorf("invalid COFF relocation in %q", section.Name)
			}
		}
	}
	return f, nil
}

func windowsCOFFBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	maximum := 64 << 20
	if err := starlark.UnpackArgs("coff", args, kwargs, "source", &source, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum <= 0 {
		return nil, fmt.Errorf("coff: maximum must be positive")
	}
	data, err := bytesForBinaryValueLimited(source, int64(maximum))
	if err != nil {
		return nil, err
	}
	f, err := parseWindowsCOFF(data)
	if err != nil {
		return nil, fmt.Errorf("coff: %w", err)
	}
	var symbols []starlark.Value
	names := make(map[uint32]string)
	for i := 0; i < len(f.COFFSymbols); {
		s := f.COFFSymbols[i]
		name, err := s.FullName(f.StringTable)
		if err != nil {
			return nil, err
		}
		names[uint32(i)] = name
		symbols = append(symbols, starvalue.NewRecord(starlark.StringDict{
			"index": starlark.MakeInt(i), "name": starlark.String(name),
			"value": starlark.MakeUint(uint(s.Value)), "section": starlark.MakeInt(int(s.SectionNumber)),
			"type": starlark.MakeInt(int(s.Type)), "storage_class": starlark.MakeInt(int(s.StorageClass)),
			"aux_count": starlark.MakeInt(int(s.NumberOfAuxSymbols)),
		}))
		i += 1 + int(s.NumberOfAuxSymbols)
	}
	var sections []starlark.Value
	for i, s := range f.Sections {
		// Uninitialized sections have a declared size but no file-backed bytes.
		contents := starlark.Bytes("")
		if s.Offset != 0 {
			contents = starlark.Bytes(data[s.Offset : uint64(s.Offset)+uint64(s.Size)])
		}
		var relocs []starlark.Value
		for _, r := range s.Relocs {
			relocs = append(relocs, starvalue.NewRecord(starlark.StringDict{
				"offset": starlark.MakeUint(uint(r.VirtualAddress)), "type": starlark.MakeInt(int(r.Type)),
				"symbol_index": starlark.MakeUint(uint(r.SymbolTableIndex)), "symbol": starlark.String(names[r.SymbolTableIndex]),
			}))
		}
		sections = append(sections, starvalue.NewRecord(starlark.StringDict{
			"index": starlark.MakeInt(i + 1), "name": starlark.String(s.Name), "data": contents,
			"size": starlark.MakeUint(uint(s.Size)), "characteristics": starlark.MakeUint(uint(s.Characteristics)),
			"relocations": starlark.NewList(relocs),
		}))
	}
	return starvalue.NewRecord(starlark.StringDict{
		"machine": starlark.MakeInt(int(f.Machine)), "sections": starlark.NewList(sections), "symbols": starlark.NewList(symbols),
	}), nil
}
