package power

import (
	"fmt"
	"maps"
)

// Virtual-bus TCEs use 4KB pages, a 40-bit real page number, an eight-bit
// partition owner, and separate valid/all-partitions/write bits. Cache bits
// above the RPN are retained but do not participate in address translation.
// This is the legacy virtual-bus format, not the PCI TCE format.
const tceRPN = uint64(0x000ffffffffff000)

type tceTable struct {
	count   uint64
	entries map[uint64]uint64
}

func cloneTCEs(tables map[uint64]*tceTable) map[uint64]*tceTable {
	out := make(map[uint64]*tceTable, len(tables))
	for id, t := range tables {
		out[id] = &tceTable{t.count, maps.Clone(t.entries)}
	}
	return out
}

// CreateTCETable configures an initially unmapped virtual-bus DMA window.
// Table identifiers are opaque backend-assigned tokens. Storage is sparse.
func (m *Machine) CreateTCETable(index, entries uint64) error {
	if entries == 0 || entries > ^uint64(0)>>12 {
		return fmt.Errorf("power: invalid TCE table size %x", entries)
	}
	if m.tces[index] != nil {
		return fmt.Errorf("power: TCE table %x already exists", index)
	}
	if m.tces == nil {
		m.tces = make(map[uint64]*tceTable)
	}
	m.tces[index] = &tceTable{entries, make(map[uint64]uint64)}
	return nil
}

// ReadTCE reads an entry, including invalid entries, without translating it.
func (m *Machine) ReadTCE(index, slot uint64) (uint64, error) {
	t := m.tces[index]
	if t == nil || slot >= t.count {
		return 0, fmt.Errorf("power: unknown TCE %x/%x", index, slot)
	}
	return t.entries[slot], nil
}

// validateTCE checks an update without changing the table.
func (m *Machine) validateTCE(index, slot, word uint64) error {
	t := m.tces[index]
	if t == nil || slot >= t.count {
		return fmt.Errorf("power: unknown TCE %x/%x", index, slot)
	}
	real := word & tceRPN
	if word&0x800 != 0 && (real > uint64(len(m.Mem)) || uint64(len(m.Mem))-real < 4096) {
		return fmt.Errorf("power: TCE real page %x outside memory", real)
	}
	return nil
}

// WriteTCE updates one entry, validating it before changing table contents.
func (m *Machine) WriteTCE(index, slot, word uint64) error {
	if err := m.validateTCE(index, slot, word); err != nil {
		return err
	}
	t := m.tces[index]
	if word == 0 {
		delete(t.entries, slot)
	} else {
		t.entries[slot] = word
	}
	return nil
}

// WriteTCEs atomically installs consecutive entries. An invalid slot or real
// page leaves every previous mapping unchanged, including earlier entries.
func (m *Machine) WriteTCEs(index, first uint64, words []uint64) error {
	t := m.tces[index]
	if t == nil || first > t.count || uint64(len(words)) > t.count-first {
		return fmt.Errorf("power: TCE batch %x/%x+%x outside table", index, first, len(words))
	}
	for i, w := range words {
		if err := m.validateTCE(index, first+uint64(i), w); err != nil {
			return err
		}
	}
	for i, w := range words {
		if err := m.WriteTCE(index, first+uint64(i), w); err != nil {
			return err
		}
	}
	return nil
}

func (m *Machine) dmaTable(index, address uint64, size int, lp uint8, write bool) (*tceTable, error) {
	t := m.tces[index]
	if t == nil {
		return nil, fmt.Errorf("power: unknown TCE table %x", index)
	}
	limit := t.count << 12
	if size < 0 || address > limit || uint64(size) > limit-address {
		return nil, fmt.Errorf("power: DMA range %x+%x outside TCE window", address, size)
	}
	for a, left := address, uint64(size); left > 0; {
		w := t.entries[a>>12]
		if w&0x800 == 0 || (w&0x400 == 0 && uint8(w>>2) != lp) || (write && w&1 == 0) {
			return nil, fmt.Errorf("power: DMA access denied at %x for partition %x", a, lp)
		}
		n := min(left, 4096-(a&4095))
		a, left = a+n, left-n
	}
	return t, nil
}

// ReadDMA copies from a checked virtual-bus DMA window into backend memory.
// The entire range is validated before the destination is changed.
func (m *Machine) ReadDMA(index, address uint64, dst []byte, lp uint8) error {
	t, err := m.dmaTable(index, address, len(dst), lp, false)
	if err != nil {
		return err
	}
	for len(dst) > 0 {
		real := (t.entries[address>>12] & tceRPN) | (address & 4095)
		n := min(len(dst), int(4096-(address&4095)))
		copy(dst[:n], m.Mem[real:real+uint64(n)])
		address, dst = address+uint64(n), dst[n:]
	}
	return nil
}

// WriteDMA copies backend bytes into guest memory. It validates every page
// before changing any bytes, and clears pointer tags and CPU reservations.
func (m *Machine) WriteDMA(index, address uint64, src []byte, lp uint8) error {
	t, err := m.dmaTable(index, address, len(src), lp, true)
	if err != nil {
		return err
	}
	for len(src) > 0 {
		real := (t.entries[address>>12] & tceRPN) | (address & 4095)
		n := min(len(src), int(4096-(address&4095)))
		if err := m.WriteReal(real, src[:n]); err != nil {
			return err
		}
		address, src = address+uint64(n), src[n:]
	}
	return nil
}
