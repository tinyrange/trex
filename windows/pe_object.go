package windows

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"

	"go.starlark.net/starlark"
)

// windowsPE is the typed, lazy Starlark view of a Portable Executable image.
// Parsing and binary transformations remain in Go; version-specific policy
// belongs in Starlark modules that consume this object.
type windowsPE struct {
	file           starfile.File
	cache          starlark.StringDict
	materialized   starfile.File
	materializeErr error
}

func peObjectBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("pe", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pe: got %s, want file", value.Type())
	}
	return &windowsPE{file: file, cache: make(starlark.StringDict)}, nil
}

func (p *windowsPE) String() string        { return fmt.Sprintf("<windows.pe size=%d>", p.file.Size()) }
func (p *windowsPE) Type() string          { return "windows.pe" }
func (p *windowsPE) Freeze()               {}
func (p *windowsPE) Truth() starlark.Bool  { return starlark.True }
func (p *windowsPE) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", p.Type()) }
func (p *windowsPE) AttrNames() []string {
	return []string{"amd64_unwind", "codeview", "data", "disasm", "exports", "imports", "info", "messages", "patch", "pointer_string_tables", "read", "resources", "sections", "typelibs", "version"}
}
func (p *windowsPE) Attr(name string) (starlark.Value, error) {
	if value, ok := p.cache[name]; ok {
		return value, nil
	}
	var property func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error)
	switch name {
	case "codeview":
		property = peCodeViewBuiltin
	case "exports":
		property = peExportsBuiltin
	case "imports":
		property = peImportsBuiltin
	case "info":
		property = peInfoBuiltin
	case "messages":
		property = peMessagesBuiltin
	case "resources":
		property = peResourcesBuiltin
	case "sections":
		property = peSectionsBuiltin
	case "typelibs":
		property = peTypeLibsBuiltin
	case "version":
		property = peVersionBuiltin
	}
	if property != nil {
		source, err := p.sourceFile()
		if err != nil {
			return nil, err
		}
		value, err := property(nil, nil, starlark.Tuple{source}, nil)
		if err != nil {
			return nil, err
		}
		value.Freeze()
		p.cache[name] = value
		return value, nil
	}
	if name == "data" {
		source, err := p.sourceFile()
		if err != nil {
			return nil, err
		}
		value := source
		p.cache[name] = value
		return value, nil
	}
	var method func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error)
	switch name {
	case "amd64_unwind":
		method = p.amd64UnwindBuiltin
	case "disasm":
		method = p.disasmBuiltin
	case "patch":
		method = p.patchBuiltin
	case "pointer_string_tables":
		method = p.pointerStringTablesBuiltin
	case "read":
		method = p.readBuiltin
	}
	if method != nil {
		value := starlark.NewBuiltin(name, method)
		p.cache[name] = value
		return value, nil
	}
	return nil, nil
}

func (p *windowsPE) sourceFile() (starfile.File, error) {
	if p.materialized != nil || p.materializeErr != nil {
		return p.materialized, p.materializeErr
	}
	data, err := starfile.ReadAll(p.file)
	if err != nil {
		p.materializeErr = err
		return nil, err
	}
	p.materialized = &starfile.Bytes{Name: p.file.String(), Data: data}
	return p.materialized, nil
}

func (p *windowsPE) pointerStringTablesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	suffix := ""
	minimum, maximum := 2, 260
	if err := starlark.UnpackArgs("pointer_string_tables", args, kwargs, "suffix?", &suffix, "minimum?", &minimum, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if minimum < 1 || maximum < 1 || maximum > 1<<20 {
		return nil, fmt.Errorf("pointer_string_tables: invalid minimum or maximum")
	}
	source, err := p.sourceFile()
	if err != nil {
		return nil, err
	}
	data, err := starfile.ReadAll(source)
	if err != nil {
		return nil, err
	}
	image, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer image.Close()

	var imageBase uint64
	pointerSize := 4
	switch optional := image.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(optional.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = optional.ImageBase
		pointerSize = 8
	default:
		return starlark.NewList(nil), nil
	}
	wanted := strings.ToLower(suffix)
	resolve := func(address uint64) (string, bool) {
		if address < imageBase || address-imageBase > uint64(^uint32(0)) {
			return "", false
		}
		rawOffset, err := peRVAOffset(image, uint32(address-imageBase))
		offset := int(rawOffset)
		if err != nil || offset < 0 || offset >= len(data) {
			return "", false
		}
		end := offset
		limit := min(len(data), offset+maximum)
		for end < limit && data[end] != 0 {
			if data[end] != '\t' && (data[end] < 0x20 || data[end] > 0x7e) {
				return "", false
			}
			end++
		}
		if end == offset || end == limit || data[end] != 0 {
			return "", false
		}
		value := string(data[offset:end])
		return value, wanted == "" || strings.HasSuffix(strings.ToLower(value), wanted)
	}

	var tables []starlark.Value
	for _, section := range image.Sections {
		start, end := int(section.Offset), int(section.Offset+section.Size)
		if start < 0 || end < start || end > len(data) {
			continue
		}
		for offset := start; offset+pointerSize <= end; {
			readPointer := func(at int) uint64 {
				if pointerSize == 8 {
					return binary.LittleEndian.Uint64(data[at : at+8])
				}
				return uint64(binary.LittleEndian.Uint32(data[at : at+4]))
			}
			first, ok := resolve(readPointer(offset))
			if !ok {
				offset += pointerSize
				continue
			}
			values := []starlark.Value{starlark.String(first)}
			cursor := offset + pointerSize
			for cursor+pointerSize <= end {
				value, ok := resolve(readPointer(cursor))
				if !ok {
					break
				}
				values = append(values, starlark.String(value))
				cursor += pointerSize
			}
			if len(values) >= minimum {
				tables = append(tables, starlark.NewList(values))
			}
			offset = cursor
		}
	}
	return starlark.NewList(tables), nil
}

func (p *windowsPE) disasmBuiltin(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	source, err := p.sourceFile()
	if err != nil {
		return nil, err
	}
	return peDisasmBuiltin(thread, builtin, append(starlark.Tuple{source}, args...), kwargs)
}

func (p *windowsPE) patchBuiltin(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	source, err := p.sourceFile()
	if err != nil {
		return nil, err
	}
	return pePatchBuiltin(thread, builtin, append(starlark.Tuple{source}, args...), kwargs)
}

func (p *windowsPE) readBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var rva uint64
	var size int
	if err := starlark.UnpackArgs("read", args, kwargs, "rva", &rva, "size", &size); err != nil {
		return nil, err
	}
	if rva > uint64(^uint32(0)) || size < 0 || size > defaultBinaryBuilderLimit {
		return nil, fmt.Errorf("read: invalid RVA or size")
	}
	source, err := p.sourceFile()
	if err != nil {
		return nil, err
	}
	data, err := starfile.ReadAll(source)
	if err != nil {
		return nil, err
	}
	image, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer image.Close()
	offset, err := peRVAOffset(image, uint32(rva))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if uint64(offset) > uint64(len(data)) || uint64(size) > uint64(len(data))-uint64(offset) {
		return nil, fmt.Errorf("read: range at RVA %#x exceeds file", rva)
	}
	return starlark.Bytes(bytes.Clone(data[offset : int(offset)+size])), nil
}
