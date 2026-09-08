package cpu

import (
	"bytes"
	"fmt"
	"math"
	"sort"
)

type region struct {
	start  uint64
	data   []byte
	access Access
}

// AddressSpace is a bounded, sparse, in-memory guest address space. It owns
// mapping bytes; callers cannot mutate memory through retained input slices.
type AddressSpace struct {
	regions     []region
	limit       uint64
	used        uint64
	protections []Protection
	readCache   [64]permissionSpan
}

// A cache entry never straddles an effective protection boundary, even when
// Protect is called on a sub-page range. Bytes are private aliases of owned
// mappings; every successful mapping/permission mutation invalidates entries.
type permissionSpan struct {
	start  uint64
	data   []byte
	access Access
}

func (m *AddressSpace) cachedSpan(address uint64, size int, access Access) []byte {
	entry := &m.readCache[(address>>12)%uint64(len(m.readCache))]
	if address < entry.start || size < 0 || entry.access&access != access {
		return nil
	}
	offset := address - entry.start
	if offset > uint64(len(entry.data)) || uint64(size) > uint64(len(entry.data))-offset {
		return nil
	}
	return entry.data[offset : offset+uint64(size)]
}

func (m *AddressSpace) cacheSpan(address uint64, r *region) {
	start := max(r.start, address&^uint64(4095))
	for _, p := range m.protections {
		if p.Start <= address {
			start = max(start, p.Start)
			if address-p.Start >= p.Size {
				start = max(start, p.Start+p.Size)
			}
		}
	}
	access, available := m.accessAt(start, r)
	available = min(available, 4096-int(start&4095))
	entry := &m.readCache[(address>>12)%uint64(len(m.readCache))]
	*entry = permissionSpan{start: start, data: r.data[start-r.start : start-r.start+uint64(available)], access: access}
}

type Protection struct {
	Start, Size uint64
	Access      Access
}

// Mapping describes one contiguous effective-permission range. Base identifies
// the original allocation even when protection changes split its visible view.
type Mapping struct {
	Start, Size, Base uint64
	Access            Access
}

// Mappings returns an owned, address-sorted view without exposing guest bytes.
func (m *AddressSpace) Mappings() []Mapping {
	var mappings []Mapping
	for i := range m.regions {
		r := &m.regions[i]
		for offset := uint64(0); offset < uint64(len(r.data)); {
			address := r.start + offset
			access, available := m.accessAt(address, r)
			mappings = append(mappings, Mapping{Start: address, Size: uint64(available), Base: r.start, Access: access})
			offset += uint64(available)
		}
	}
	return mappings
}

func (m *AddressSpace) accessAt(address uint64, r *region) (Access, int) {
	access := r.access
	available := len(r.data) - int(address-r.start)
	for _, p := range m.protections {
		if address >= p.Start && address-p.Start < p.Size {
			access = p.Access
			available = min(available, int(p.Size-(address-p.Start)))
		} else if p.Start > address && p.Start-address < uint64(available) {
			available = int(p.Start - address)
		}
	}
	return access, available
}

func NewAddressSpace(limit uint64) *AddressSpace { return &AddressSpace{limit: limit} }

func validRange(address uint64, size int) bool {
	return size >= 0 && (size == 0 || uint64(size-1) <= math.MaxUint64-address)
}

func (m *AddressSpace) Map(address uint64, data []byte, access Access) error {
	if len(data) == 0 || !validRange(address, len(data)) || access == 0 || access & ^(Read|Write|Execute) != 0 {
		return fmt.Errorf("memory: invalid mapping at %#x", address)
	}
	if uint64(len(data)) > m.limit-m.used {
		return fmt.Errorf("memory: mapping exceeds %d-byte budget", m.limit)
	}
	last := address + uint64(len(data)-1)
	for _, r := range m.regions {
		if address <= r.start+uint64(len(r.data)-1) && r.start <= last {
			return fmt.Errorf("memory: overlapping mapping at %#x", address)
		}
	}
	m.regions = append(m.regions, region{address, bytes.Clone(data), access})
	sort.Slice(m.regions, func(i, j int) bool { return m.regions[i].start < m.regions[j].start })
	m.used += uint64(len(data))
	clear(m.readCache[:])
	return nil
}

func (m *AddressSpace) find(address uint64) *region {
	i := sort.Search(len(m.regions), func(i int) bool { return m.regions[i].start > address }) - 1
	if i < 0 || address-m.regions[i].start >= uint64(len(m.regions[i].data)) {
		return nil
	}
	return &m.regions[i]
}

func (m *AddressSpace) check(address uint64, size int, access Access) error {
	if !validRange(address, size) {
		return fmt.Errorf("memory: range overflows at %#x", address)
	}
	if m.cachedSpan(address, size, access) != nil {
		return nil
	}
	for remaining := size; remaining > 0; {
		r := m.find(address)
		if r == nil {
			return fmt.Errorf("memory: access %d denied at %#x", access, address)
		}
		permissions, available := m.accessAt(address, r)
		if permissions&access != access {
			return fmt.Errorf("memory: access %d denied at %#x", access, address)
		}
		n := min(remaining, available)
		remaining -= n
		if remaining != 0 {
			address += uint64(n)
		}
	}
	return nil
}

func (m *AddressSpace) CheckMemory(address uint64, size int, access Access) error {
	if access == 0 || access & ^(Read|Write|Execute) != 0 {
		return fmt.Errorf("memory: invalid access %d", access)
	}
	return m.check(address, size, access)
}

func (m *AddressSpace) ReadMemory(address uint64, destination []byte, access Access) error {
	if access != Read && access != Execute {
		return fmt.Errorf("memory: invalid read access %d", access)
	}
	if source := m.cachedSpan(address, len(destination), access); source != nil {
		copy(destination, source)
		return nil
	}
	if validRange(address, len(destination)) {
		if r := m.find(address); r != nil {
			m.cacheSpan(address, r)
			if source := m.cachedSpan(address, len(destination), access); source != nil {
				copy(destination, source)
				return nil
			}
		}
	}
	if err := m.check(address, len(destination), access); err != nil {
		return err
	}
	for len(destination) > 0 {
		r := m.find(address)
		n := copy(destination, r.data[address-r.start:])
		destination = destination[n:]
		if len(destination) != 0 {
			address += uint64(n)
		}
	}
	return nil
}

func (m *AddressSpace) WriteMemory(address uint64, source []byte) error {
	if err := m.check(address, len(source), Write); err != nil {
		return err
	}
	for len(source) > 0 {
		r := m.find(address)
		n := copy(r.data[address-r.start:], source)
		source = source[n:]
		if len(source) != 0 {
			address += uint64(n)
		}
	}
	return nil
}

func (m *AddressSpace) Clone() *AddressSpace {
	clone := &AddressSpace{limit: m.limit, used: m.used}
	clone.protections = append([]Protection(nil), m.protections...)
	for _, r := range m.regions {
		clone.regions = append(clone.regions, region{r.start, bytes.Clone(r.data), r.access})
	}
	return clone
}

// Unmap removes exactly one complete mapping and releases its budget.
func (m *AddressSpace) Unmap(address uint64) error {
	for i, r := range m.regions {
		if r.start == address {
			last := address + uint64(len(r.data)-1)
			var remaining []Protection
			for _, p := range m.protections {
				pLast := p.Start + p.Size - 1
				if pLast < address || p.Start > last {
					remaining = append(remaining, p)
					continue
				}
				if p.Start < address {
					remaining = append(remaining, Protection{p.Start, address - p.Start, p.Access})
				}
				if pLast > last {
					remaining = append(remaining, Protection{last + 1, pLast - last, p.Access})
				}
			}
			m.protections = remaining
			m.used -= uint64(len(r.data))
			m.regions = append(m.regions[:i], m.regions[i+1:]...)
			clear(m.readCache[:])
			return nil
		}
	}
	return fmt.Errorf("memory: no mapping starts at %#x", address)
}

// Protect changes permissions over a fully mapped range, returning its prior
// effective permissions. A failed operation leaves all mappings unchanged.
func (m *AddressSpace) Protect(address uint64, size int, access Access) ([]Protection, error) {
	if size <= 0 || access & ^(Read|Write|Execute) != 0 {
		return nil, fmt.Errorf("memory: invalid protection")
	}
	if err := m.check(address, size, 0); err != nil {
		return nil, err
	}
	var previous []Protection
	for location, remaining := address, size; remaining > 0; {
		r := m.find(location)
		permissions, available := m.accessAt(location, r)
		n := min(remaining, available)
		previous = append(previous, Protection{location, uint64(n), permissions})
		remaining -= n
		if remaining != 0 {
			location += uint64(n)
		}
	}
	m.protections = append(m.protections, Protection{address, uint64(size), access})
	clear(m.readCache[:])
	return previous, nil
}
