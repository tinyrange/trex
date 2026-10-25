package windows

import (
	"encoding/binary"
	"fmt"

	starvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
)

type windowsNEImport struct {
	Module, Name                     string
	Ordinal, Segment, Offset, Source int
	Additive                         bool
}

// parseWindowsNEImports returns imported relocation heads. It does not apply
// fixups or traverse loader-linked relocation chains in segment contents.
func parseWindowsNEImports(data []byte, maximum int) ([]windowsNEImport, error) {
	m, err := parseWindowsNEModule(data)
	if err != nil {
		return nil, err
	}
	refs := m.ne + int(binary.LittleEndian.Uint16(data[m.ne+0x28:]))
	count := int(binary.LittleEndian.Uint16(data[m.ne+0x1e:]))
	names := m.ne + int(binary.LittleEndian.Uint16(data[m.ne+0x2a:]))
	if refs < m.ne+64 || refs > len(data) || count > (len(data)-refs)/2 || names < m.ne+64 || names > m.nonresident {
		return nil, fmt.Errorf("invalid NE import tables")
	}
	nameAt := func(offset int) (string, error) {
		if offset >= m.nonresident-names {
			return "", fmt.Errorf("NE imported-name offset exceeds table")
		}
		at := names + offset
		length := int(data[at])
		if length == 0 || length > m.nonresident-at-1 {
			return "", fmt.Errorf("invalid NE imported name")
		}
		return string(data[at+1 : at+1+length]), nil
	}
	modules := make([]string, count)
	for i := range count {
		modules[i], err = nameAt(int(binary.LittleEndian.Uint16(data[refs+i*2:])))
		if err != nil {
			return nil, err
		}
	}
	var imports []windowsNEImport
	for segment := 0; segment < m.segmentCount; segment++ {
		entry := m.segments + segment*8
		flags := binary.LittleEndian.Uint16(data[entry+4:])
		if flags&0x100 == 0 {
			continue
		}
		if flags&8 != 0 {
			return nil, fmt.Errorf("NE iterated segment relocations are unsupported")
		}
		base := uint64(binary.LittleEndian.Uint16(data[entry:])) << m.alignShift
		length := windowsNEExpandedLength(binary.LittleEndian.Uint16(data[entry+2:]))
		at := base + length
		if base == 0 || at > uint64(len(data)) || uint64(len(data))-at < 2 {
			return nil, fmt.Errorf("NE segment %d has truncated relocations", segment+1)
		}
		fixups := int(binary.LittleEndian.Uint16(data[at:]))
		at += 2
		if fixups > (len(data)-int(at))/8 {
			return nil, fmt.Errorf("NE segment %d has truncated relocations", segment+1)
		}
		for range fixups {
			p := data[at : at+8]
			at += 8
			kind := p[1] & 3
			if kind != 1 && kind != 2 {
				continue
			}
			if len(imports) == maximum {
				return nil, fmt.Errorf("NE imports exceed maximum %d", maximum)
			}
			module := int(binary.LittleEndian.Uint16(p[4:]))
			offset := int(binary.LittleEndian.Uint16(p[2:]))
			width := 0
			switch p[0] {
			case 0:
				width = 1
			case 2, 5:
				width = 2
			case 3, 13:
				width = 4
			case 11:
				width = 6
			default:
				return nil, fmt.Errorf("unsupported NE relocation source type %#x", p[0])
			}
			if module == 0 || module > len(modules) || uint64(offset+width) > length {
				return nil, fmt.Errorf("invalid NE import relocation")
			}
			item := windowsNEImport{Module: modules[module-1], Segment: segment + 1, Offset: offset, Source: int(p[0]), Additive: p[1]&4 != 0}
			target := int(binary.LittleEndian.Uint16(p[6:]))
			if kind == 1 {
				item.Ordinal = target
			} else {
				item.Name, err = nameAt(target)
				if err != nil {
					return nil, err
				}
			}
			imports = append(imports, item)
		}
	}
	return imports, nil
}

func windowsNEImportsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	maximum, maximumImports := windowsNEFastBootMaximum, 4096
	if err := starlark.UnpackArgs("ne_imports", args, kwargs, "source", &source, "maximum?", &maximum, "maximum_imports?", &maximumImports); err != nil {
		return nil, err
	}
	if maximum <= 0 || maximumImports <= 0 || maximumImports > 1<<20 {
		return nil, fmt.Errorf("ne_imports: invalid resource limit")
	}
	data, err := bytesForBinaryValueLimited(source, int64(maximum))
	if err != nil {
		return nil, err
	}
	imports, err := parseWindowsNEImports(data, maximumImports)
	if err != nil {
		return nil, fmt.Errorf("ne_imports: %w", err)
	}
	values := make([]starlark.Value, len(imports))
	for i, item := range imports {
		name, ordinal := starlark.Value(starlark.None), starlark.Value(starlark.None)
		if item.Name != "" {
			name = starlark.String(item.Name)
		} else {
			ordinal = starlark.MakeInt(item.Ordinal)
		}
		values[i] = starvalue.NewRecord(starlark.StringDict{
			"module": starlark.String(item.Module), "name": name, "ordinal": ordinal,
			"segment": starlark.MakeInt(item.Segment), "offset": starlark.MakeInt(item.Offset),
			"source_type": starlark.MakeInt(item.Source), "additive": starlark.Bool(item.Additive),
		})
	}
	return starlark.NewList(values), nil
}
