package elfmeta

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// BTF v1 type kinds from Linux's uapi/linux/btf.h. Each type begins with
// three u32s and may carry a fixed or vlen-sized trailer.
func btfTypeExtraSize(kind, vlen uint32) (uint32, error) {
	switch kind {
	case 0, 2, 7, 8, 9, 10, 11, 12, 16, 18:
		return 0, nil
	case 1, 14, 17:
		return 4, nil
	case 3:
		return 12, nil
	case 4, 5, 15, 19:
		return vlen * 12, nil
	case 6, 13:
		return vlen * 8, nil
	default:
		return 0, fmt.Errorf("elf_structs: unsupported BTF kind %d", kind)
	}
}

func readBTFLayouts(data []byte, names []string) (map[string]StructLayout, error) {
	wanted, err := requestedStructs(names)
	if err != nil {
		return nil, err
	}
	const headerSize = 24
	if len(data) < headerSize || data[2] != 1 || data[3] != 0 {
		return nil, fmt.Errorf("elf_structs: invalid BTF v1 header")
	}
	var order binary.ByteOrder
	switch {
	case binary.LittleEndian.Uint16(data) == 0xeb9f:
		order = binary.LittleEndian
	case binary.BigEndian.Uint16(data) == 0xeb9f:
		order = binary.BigEndian
	default:
		return nil, fmt.Errorf("elf_structs: invalid BTF magic")
	}
	u32 := order.Uint32
	head := uint64(u32(data[4:]))
	typeOff, typeLen := uint64(u32(data[8:])), uint64(u32(data[12:]))
	strOff, strLen := uint64(u32(data[16:])), uint64(u32(data[20:]))
	if head < headerSize || head+strOff+strLen > uint64(len(data)) || typeOff+typeLen > strOff || strLen == 0 {
		return nil, fmt.Errorf("elf_structs: invalid BTF section extents")
	}
	types := data[head+typeOff : head+typeOff+typeLen]
	strings := data[head+strOff : head+strOff+strLen]
	if strings[0] != 0 || strings[len(strings)-1] != 0 {
		return nil, fmt.Errorf("elf_structs: invalid BTF string table")
	}
	nameAt := func(offset uint32) (string, error) {
		if uint64(offset) < uint64(len(strings)) {
			name := strings[offset:]
			if end := bytes.IndexByte(name[:min(len(name), 4096)], 0); end >= 0 {
				return string(name[:end]), nil
			}
		}
		return "", fmt.Errorf("elf_structs: invalid or over-limit BTF name at %#x", offset)
	}

	out := make(map[string]StructLayout, len(names))
	aggregates := make(map[uint32][]byte)
	selected := make(map[uint32]string)
	for id := uint32(1); len(types) != 0; id++ {
		if len(types) < 12 {
			return nil, fmt.Errorf("elf_structs: truncated BTF type")
		}
		info := u32(types[4:])
		kind, vlen := (info>>24)&0x1f, info&0xffff
		extra, err := btfTypeExtraSize(kind, vlen)
		if err != nil {
			return nil, err
		}
		if uint64(12+extra) > uint64(len(types)) {
			return nil, fmt.Errorf("elf_structs: truncated BTF type trailer")
		}
		entry := types[:12+extra]
		types = types[12+extra:]
		if kind != 4 && kind != 5 { // BTF_KIND_STRUCT or BTF_KIND_UNION
			continue
		}
		aggregates[id] = entry
		if kind == 5 {
			continue
		}
		name, err := nameAt(u32(entry))
		if err != nil {
			return nil, err
		}
		if wanted[name] {
			selected[id] = name
		}
	}
	for id, name := range selected {
		entry := aggregates[id]
		size := uint64(u32(entry[8:]))
		fields := make(map[string]uint64)
		budget := 65536
		if err := readBTFMembers(entry, u32, nameAt, aggregates, fields, 0, 0, &budget); err != nil {
			return nil, fmt.Errorf("elf_structs: %s: %w", name, err)
		}
		if err := setStructLayout(out, name, StructLayout{Size: size, Fields: fields}); err != nil {
			return nil, err
		}
	}
	return requireStructs(out, names)
}

func readBTFMembers(entry []byte, u32 func([]byte) uint32, nameAt func(uint32) (string, error), aggregates map[uint32][]byte, fields map[string]uint64, base uint64, depth int, budget *int) error {
	if depth == 32 {
		return fmt.Errorf("BTF anonymous member nesting exceeds 32 levels")
	}
	size := uint64(u32(entry[8:]))
	flag := u32(entry[4:])>>31 != 0
	for member := entry[12:]; len(member) != 0; member = member[12:] {
		*budget = *budget - 1
		if *budget < 0 {
			return fmt.Errorf("BTF member count exceeds traversal limit")
		}
		bitOffset := u32(member[8:])
		if (flag && bitOffset>>24 != 0) || bitOffset%8 != 0 {
			continue // Bitfields do not have an independent byte location.
		}
		field, err := nameAt(u32(member))
		if err != nil {
			return err
		}
		offset := uint64(bitOffset) / 8
		if offset > size {
			return fmt.Errorf("invalid BTF member extent")
		}
		if field == "" {
			child := aggregates[u32(member[4:])]
			if len(child) == 0 || uint64(u32(child[8:])) > size-offset {
				return fmt.Errorf("invalid BTF anonymous aggregate")
			}
			if err := readBTFMembers(child, u32, nameAt, aggregates, fields, base+offset, depth+1, budget); err != nil {
				return err
			}
			continue
		}
		if prior, ok := fields[field]; ok && prior != base+offset {
			return fmt.Errorf("ambiguous BTF member %q", field)
		}
		fields[field] = base + offset
	}
	return nil
}
