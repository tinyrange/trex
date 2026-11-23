package memory

import (
	"encoding/binary"
	"fmt"
)

// AMD64Mapping describes a range mapped with 4 KiB pages.
type AMD64Mapping struct {
	Virtual, Physical, Size uint64
	Writable, Execute       bool
}

// AMD64UserMapping describes a mapping supplied in the user range list.
type AMD64UserMapping = AMD64Mapping

// AMD64UserPageTables makes a new four-level root and lower-half page tables.
// The 4 KiB kernel root contributes only its upper 256 entries. The caller
// places the returned bytes at base and retains the existing kernel tables at
// their original physical addresses. Supervisor mappings may use unused
// upper-half PML4 entries and are inaccessible from userspace.
func AMD64UserPageTables(kernelRoot []byte, base uint64, mappings []AMD64Mapping, supervisor ...AMD64Mapping) ([]byte, error) {
	const pageSize = uint64(4096)
	const tableLimit = 4 << 20
	const physicalLimit = uint64(1) << 52
	const userLimit = uint64(1) << 47
	const supervisorStart = ^uint64(0) - userLimit + 1
	if len(kernelRoot) != int(pageSize) || base == 0 || base%pageSize != 0 || base > physicalLimit-tableLimit {
		return nil, fmt.Errorf("invalid AMD64 paging root or table base")
	}
	tables := make([]byte, pageSize)
	copy(tables[pageSize/2:], kernelRoot[pageSize/2:])
	var total uint64
	for level, regions := range [2][]AMD64Mapping{mappings, supervisor} {
		user := level == 0
		for _, mapping := range regions {
			if mapping.Size == 0 || (mapping.Virtual|mapping.Physical|mapping.Size)%pageSize != 0 ||
				mapping.Physical >= physicalLimit || mapping.Size > physicalLimit-mapping.Physical {
				return nil, fmt.Errorf("invalid AMD64 mapping at %#x", mapping.Virtual)
			}
			if user && (mapping.Virtual >= userLimit || mapping.Size > userLimit-mapping.Virtual) ||
				!user && (mapping.Virtual < supervisorStart || mapping.Size-1 > ^uint64(0)-mapping.Virtual) {
				return nil, fmt.Errorf("invalid AMD64 mapping privilege at %#x", mapping.Virtual)
			}
			if mapping.Size > (1<<30)-total {
				return nil, fmt.Errorf("AMD64 mappings exceed 1 GiB")
			}
			total += mapping.Size
			present := uint64(1)
			if user {
				present |= 4
			}
			flags := present
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
					if !user && shift == 39 && binary.LittleEndian.Uint64(kernelRoot[index:]) != 0 {
						return nil, fmt.Errorf("AMD64 supervisor mapping overlaps a linked kernel branch at %#x", virtual)
					}
					next := binary.LittleEndian.Uint64(tables[index:])
					if next == 0 {
						if len(tables) == tableLimit {
							return nil, fmt.Errorf("AMD64 page tables exceed 4 MiB")
						}
						next = base + uint64(len(tables))
						tables = append(tables, make([]byte, pageSize)...)
						binary.LittleEndian.PutUint64(tables[index:], next|present|2)
					}
					table = (next &^ (pageSize - 1)) - base
				}
				index := table + (virtual>>12&511)*8
				if binary.LittleEndian.Uint64(tables[index:]) != 0 {
					return nil, fmt.Errorf("overlapping AMD64 mapping at %#x", virtual)
				}
				binary.LittleEndian.PutUint64(tables[index:], (mapping.Physical+offset)|flags)
			}
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
