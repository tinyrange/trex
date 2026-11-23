package memory

import (
	"encoding/binary"
	"fmt"
)

// AMD64UserMapping grants a lower-half userspace mapping with 4 KiB pages.
type AMD64UserMapping struct {
	Virtual, Physical, Size uint64
	Writable, Execute       bool
}

// AMD64UserPageTables makes a new four-level root and lower-half page tables.
// The 4 KiB kernel root contributes only its upper 256 entries. The caller
// places the returned bytes at base and retains the existing kernel tables at
// their original physical addresses.
func AMD64UserPageTables(kernelRoot []byte, base uint64, mappings []AMD64UserMapping) ([]byte, error) {
	const pageSize = uint64(4096)
	const tableLimit = 4 << 20
	const physicalLimit = uint64(1) << 52
	const userLimit = uint64(1) << 47
	const presentUser = uint64(5)
	if len(kernelRoot) != int(pageSize) || base == 0 || base%pageSize != 0 || base > physicalLimit-tableLimit {
		return nil, fmt.Errorf("invalid AMD64 paging root or table base")
	}
	tables := make([]byte, pageSize)
	copy(tables[pageSize/2:], kernelRoot[pageSize/2:])
	var total uint64
	for _, mapping := range mappings {
		if mapping.Size == 0 || (mapping.Virtual|mapping.Physical|mapping.Size)%pageSize != 0 ||
			mapping.Virtual >= userLimit || mapping.Size > userLimit-mapping.Virtual ||
			mapping.Physical >= physicalLimit || mapping.Size > physicalLimit-mapping.Physical {
			return nil, fmt.Errorf("invalid AMD64 userspace mapping at %#x", mapping.Virtual)
		}
		if mapping.Size > (1<<30)-total {
			return nil, fmt.Errorf("AMD64 userspace mappings exceed 1 GiB")
		}
		total += mapping.Size
		flags := presentUser
		if mapping.Writable {
			flags |= 2
		}
		if !mapping.Execute {
			flags |= 1 << 63
		}
		for offset := uint64(0); offset < mapping.Size; offset += pageSize {
			virtual := mapping.Virtual + offset
			table := uint64(0)
			for _, shift := range []uint{39, 30, 21} {
				index := table + (virtual>>shift&511)*8
				next := binary.LittleEndian.Uint64(tables[index:])
				if next == 0 {
					if len(tables) == tableLimit {
						return nil, fmt.Errorf("AMD64 user page tables exceed 4 MiB")
					}
					next = base + uint64(len(tables))
					tables = append(tables, make([]byte, pageSize)...)
					binary.LittleEndian.PutUint64(tables[index:], next|presentUser|2)
				}
				table = (next &^ (pageSize - 1)) - base
			}
			index := table + (virtual>>12&511)*8
			if binary.LittleEndian.Uint64(tables[index:]) != 0 {
				return nil, fmt.Errorf("overlapping AMD64 user mapping at %#x", virtual)
			}
			binary.LittleEndian.PutUint64(tables[index:], (mapping.Physical+offset)|flags)
		}
	}
	// Protect the constructed table pages from userspace aliases.
	end := base + uint64(len(tables))
	for _, mapping := range mappings {
		if mapping.Physical < end && base < mapping.Physical+mapping.Size {
			return nil, fmt.Errorf("AMD64 user mapping overlaps the page-table allocation")
		}
	}
	return tables, nil
}
