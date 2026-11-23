package elfmeta

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"io"
	"maps"
	"strings"

	"github.com/tinyrange/trex/storage"
)

// StructLayout describes a defined DWARF structure and the byte offsets of
// named members whose locations are constant.
type StructLayout struct {
	Size   uint64
	Fields map[string]uint64
}

// StructLayouts resolves named DWARF structure tags in a bounded ELF64 file.
// Repeated declarations are ignored and conflicting definitions are rejected.
func StructLayouts(source storage.Reader, names []string) (map[string]StructLayout, error) {
	if source == nil || source.Size() <= 0 || source.Size() > 128<<20 {
		return nil, fmt.Errorf("elf_structs: file size must be 1..128 MiB")
	}
	if _, err := Open(source, Options{}); err != nil {
		return nil, err
	}
	file, err := elf.NewFile(io.NewSectionReader(source, 0, source.Size()))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var debugSize uint64
	for _, section := range file.Sections {
		if strings.HasPrefix(section.Name, ".zdebug_") {
			return nil, fmt.Errorf("elf_structs: legacy GNU-compressed DWARF is unsupported")
		}
		if strings.HasPrefix(section.Name, ".debug_") || section.Type == elf.SHT_RELA || section.Type == elf.SHT_REL {
			if section.Size > (128<<20)-debugSize {
				return nil, fmt.Errorf("elf_structs: DWARF sections exceed 128 MiB")
			}
			debugSize += section.Size
		}
	}
	data, err := file.DWARF()
	if err != nil {
		return nil, fmt.Errorf("elf_structs: %w", err)
	}
	return readStructLayouts(data, names)
}

func readStructLayouts(data *dwarf.Data, names []string) (map[string]StructLayout, error) {
	if len(names) == 0 || len(names) > 64 {
		return nil, fmt.Errorf("elf_structs: expected 1..64 structure names")
	}
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		if name == "" || wanted[name] {
			return nil, fmt.Errorf("elf_structs: empty or duplicate structure name %q", name)
		}
		wanted[name] = true
	}

	out := make(map[string]StructLayout, len(names))
	reader := data.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, err
		}
		if entry == nil {
			break
		}
		if entry.Tag != dwarf.TagStructType || !entry.Children {
			continue
		}
		name, _ := entry.Val(dwarf.AttrName).(string)
		size, _ := entry.Val(dwarf.AttrByteSize).(int64)
		if !wanted[name] || size <= 0 {
			continue
		}
		fields, err := readStructMembers(reader, uint64(size))
		if err != nil {
			return nil, fmt.Errorf("elf_structs: %s: %w", name, err)
		}
		if prior, ok := out[name]; ok && (prior.Size != uint64(size) || !maps.Equal(prior.Fields, fields)) {
			return nil, fmt.Errorf("elf_structs: conflicting definitions of %q", name)
		}
		out[name] = StructLayout{Size: uint64(size), Fields: fields}
	}
	for _, name := range names {
		if _, ok := out[name]; !ok {
			return nil, fmt.Errorf("elf_structs: no definition of %q", name)
		}
	}
	return out, nil
}

func readStructMembers(reader *dwarf.Reader, size uint64) (map[string]uint64, error) {
	fields := make(map[string]uint64)
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, err
		}
		if entry == nil {
			return nil, fmt.Errorf("unterminated member list")
		}
		if entry.Tag == 0 {
			return fields, nil
		}
		if entry.Tag == dwarf.TagMember {
			name, _ := entry.Val(dwarf.AttrName).(string)
			offset, ok := entry.Val(dwarf.AttrDataMemberLoc).(int64)
			if name != "" && ok {
				if offset < 0 || uint64(offset) > size || len(fields) == 4096 {
					return nil, fmt.Errorf("invalid member extent or count")
				}
				fields[name] = uint64(offset)
			}
		}
		if entry.Children {
			reader.SkipChildren()
		}
	}
}
