package machine

import "fmt"

// imageBase retains the preferred address if available; otherwise it finds a
// 64-KiB-aligned gap below the emulator's heap and semantic-dispatch arenas.
// Placement does not mutate memory: missing or invalid PE relocations can
// therefore fail without leaving an allocation or partially loaded module.
func (m *Machine) imageBase(preferred, size uint64) (uint64, error) {
	const alignment, fallback, limit = uint64(0x10000), uint64(0x180000000), uint64(0x600000000000)
	if size == 0 || size > limit-fallback {
		return 0, fmt.Errorf("machine: invalid image placement size")
	}
	mappings := m.memory.Mappings()
	available := preferred < limit && size <= limit-preferred
	for _, mapping := range mappings {
		overlaps := (preferred >= mapping.Start && preferred-mapping.Start < mapping.Size) ||
			(mapping.Start >= preferred && mapping.Start-preferred < size)
		if available && overlaps {
			available = false
		}
	}
	if available {
		return preferred, nil
	}
	base := fallback
	for _, mapping := range mappings {
		if mapping.Start >= limit {
			break
		}
		if mapping.Start >= base && size <= mapping.Start-base {
			return base, nil
		}
		if mapping.Size > limit-mapping.Start {
			return 0, fmt.Errorf("machine: no free image address range")
		}
		if mapping.Start+mapping.Size > base {
			end := mapping.Start + mapping.Size
			if end > limit-alignment+1 {
				return 0, fmt.Errorf("machine: no free image address range")
			}
			base = (end + alignment - 1) &^ (alignment - 1)
		}
	}
	if base > limit-size {
		return 0, fmt.Errorf("machine: no free image address range")
	}
	return base, nil
}
