package power

import (
	"fmt"
	"slices"
)

// HashedPageTable is an architected hashed page table owned by the
// hypervisor: Groups page-table entry groups (PTEGs) of eight two-doubleword
// entries, addressed by slot = group*8 + index. When a machine has one, its
// valid entries are the translations: entering, replacing or removing a slot
// updates the machine's page map, and host MapPage calls also occupy slots.
//
// Entries use the Power ISA 3.0 format: dw0 B(0:1) AVA(2:56) SW(57:60)
// L(61) H(62) V(63); dw1 PP0(0) TS(1, AS) ARPN(7:51) LP R C WIMG N(61) PP(62:63).
type HashedPageTable struct {
	Groups  uint64
	Entries [][2]uint64
	keys    []PageKey
}

const (
	hpteValid     = 1
	hpteSecondary = 2
	hpteLarge     = 4
	hpteTagSet    = uint64(1) << 62
	hpteRPNMask   = 0x01fffffffffff000
)

// SetHashedPageTable gives the machine a hypervisor-owned hashed page table
// with groups PTEGs (a power of two, at least 2048) and enters the existing
// page map into it.
func (m *Machine) SetHashedPageTable(groups uint64) error {
	if groups < 2048 || groups&(groups-1) != 0 {
		return fmt.Errorf("power: hashed page table groups must be a power of two >= 2048")
	}
	// Cached translations retain slots in the previous table.
	m.hptGen++
	m.HTAB = &HashedPageTable{Groups: groups, Entries: make([][2]uint64, groups*8), keys: make([]PageKey, groups*8)}
	m.slotVer = make([]uint32, groups*8)
	// Native blocks check slot versions only when compiled with a table.
	m.jitFlush()
	keys := make([]PageKey, 0, len(m.HPT))
	for k := range m.HPT {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b PageKey) int {
		if a.VSID != b.VSID {
			return cmpU64(a.VSID, b.VSID)
		}
		return cmpU64(a.Page, b.Page)
	})
	for _, k := range keys {
		if err := m.htabPlace(k, m.HPT[k]); err != nil {
			return err
		}
	}
	return nil
}

func cmpU64(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// HashPage returns the primary hash of a virtual page (ISA 3.0 Book III
// 5.7.7.3): VSID xor page index for 256MB segments, VSID xor VSID<<25 xor
// page index for 1TB segments, truncated to 39 bits.
func HashPage(vsid uint64, b uint8, shift uint, page uint64) uint64 {
	h := vsid ^ page
	if b == 1 {
		h = vsid ^ vsid<<25 ^ page
	}
	return h & (1<<39 - 1)
}

// Group returns the PTEG holding a page: the primary hash, or its
// complement for the secondary group, masked to the table size.
func (t *HashedPageTable) Group(vsid uint64, b uint8, shift uint, page uint64, secondary bool) uint64 {
	h := HashPage(vsid, b, shift, page)
	if secondary {
		h = ^h
	}
	return h & (t.Groups - 1)
}

// Large-page selector in HPTE R for each (base shift, actual shift).
var hpteLP = map[[2]int]uint64{
	{12, 12}: 0, {12, 16}: 7, {12, 24}: 0x38,
	{16, 16}: 1, {16, 24}: 8, {24, 24}: 0, {34, 34}: 3,
}

// ProbeHPTE searches both PTEGs for an architected translation. The base
// page size selects the hash, while the actual page size selects AVA and LP.
// On a miss, a nonnegative slot is the first available primary or secondary
// slot. Probing does not reserve it or change the table.
func (t *HashedPageTable) ProbeHPTE(vsid, offset uint64, tera bool, baseShift, actualShift int) (slot int, secondary bool, words [2]uint64, err error) {
	seg, b := 28, uint8(0)
	if tera {
		seg, b = 40, 1
	}
	lp, ok := hpteLP[[2]int{baseShift, actualShift}]
	if !ok || actualShift > seg || offset>>seg != 0 || vsid>>(78-seg) != 0 {
		return -1, false, words, fmt.Errorf("power: invalid HPT segment or page size for probe")
	}
	ava := vsid<<(seg-23) | (offset&^(uint64(1)<<actualShift-1))>>23
	want := uint64(b)<<62 | ava<<7 | hpteValid
	if actualShift != 12 {
		want |= hpteLarge
	}
	lpMask := uint64(0xf)
	if lp&8 != 0 {
		lpMask = 0xff
	}
	slot = -1
	for _, alternate := range []bool{false, true} {
		group := t.Group(vsid, b, uint(baseShift), offset>>baseShift, alternate)
		if alternate {
			want |= hpteSecondary
		}
		for i, entry := range t.Entries[group*8 : group*8+8] {
			index := int(group*8) + i
			if entry[0]&hpteValid == 0 {
				if slot < 0 {
					slot, secondary = index, alternate
				}
				continue
			}
			if entry[0]&^uint64(0x78) == want && (actualShift == 12 || entry[1]>>12&lpMask == lp) {
				return index, alternate, entry, nil
			}
		}
	}
	return slot, secondary, words, nil
}

// pteWords encodes a host page table entry for a key.
func pteWords(k PageKey, p PTE, secondary bool) (dw0, dw1 uint64) {
	seg := uint(28)
	if k.B == 1 {
		seg = 40
	}
	// Form AVA before shifting VSID into a virtual address: a virtual
	// address can exceed 64 bits, particularly with 1TB segments.
	ava := k.VSID<<(seg-23) | (k.Page<<k.Shift)>>23
	dw0 = uint64(k.B)<<62 | ava<<7 | hpteValid
	if k.Shift > 12 {
		dw0 |= hpteLarge
	}
	if secondary {
		dw0 |= hpteSecondary
	}
	dw1 = p.Real & hpteRPNMask
	if k.Shift > 12 {
		dw1 |= hpteLP[[2]int{int(k.Shift), int(k.Shift)}] << 12
	}
	if !p.Execute {
		dw1 |= 4
	}
	if p.Write {
		dw1 |= 2
	} else {
		dw1 |= 3
	}
	return dw0, dw1
}

// decodeEntry recovers the page key and host entry of a valid slot's
// doublewords: AVA holds the virtual address above bit 23, and the page
// index bits below it come from the group's hash.
func (t *HashedPageTable) decodeEntry(slot, dw0, dw1 uint64) (PageKey, PTE, error) {
	b := uint8(dw0 >> 62)
	if b > 1 {
		return PageKey{}, PTE{}, fmt.Errorf("power: unsupported segment size %d", b)
	}
	seg := uint(28)
	if b == 1 {
		seg = 40
	}
	shift := uint(12)
	if dw0&hpteLarge != 0 {
		switch dw1 >> 12 & 0xf {
		case 1, 7:
			shift = 16
		case 3:
			shift = 34
		default:
			shift = 24
		}
	}
	ava := (dw0 >> 7) & (1<<55 - 1)
	vsid := ava >> (seg - 23)
	off := (ava & (1<<(seg-23) - 1)) << 23
	page := off >> shift
	if shift < 23 {
		k := 23 - shift
		group := slot >> 3
		if dw0&hpteSecondary != 0 {
			group = ^group
		}
		low := (group ^ HashPage(vsid, b, shift, 0)) & (1<<k - 1)
		page |= low
	}
	p := PTE{Real: dw1 & hpteRPNMask &^ (1<<shift - 1), Write: dw1&3 != 3, Execute: dw1&4 == 0, Key: uint8(dw1 & 3)}
	return PageKey{VSID: vsid, B: b, Shift: uint8(shift), Page: page}, p, nil
}

// htabPlace puts a host mapping into the first free slot of its primary or
// secondary group.
func (m *Machine) htabPlace(k PageKey, p PTE) error {
	t := m.HTAB
	for _, secondary := range []bool{false, true} {
		g := t.Group(k.VSID, k.B, uint(k.Shift), k.Page, secondary)
		for i := uint64(0); i < 8; i++ {
			s := g*8 + i
			if t.Entries[s][0]&hpteValid == 0 {
				dw0, dw1 := pteWords(k, p, secondary)
				t.Entries[s] = [2]uint64{dw0, dw1}
				t.keys[s] = k
				return nil
			}
		}
	}
	return fmt.Errorf("power: hashed page table groups full for vsid %x page %x", k.VSID, k.Page)
}

// htabRemoveKey frees the slot holding a key, if any.
func (m *Machine) htabRemoveKey(k PageKey) {
	t := m.HTAB
	for _, secondary := range []bool{false, true} {
		g := t.Group(k.VSID, k.B, uint(k.Shift), k.Page, secondary)
		for i := uint64(0); i < 8; i++ {
			s := g*8 + i
			if t.Entries[s][0]&hpteValid != 0 && t.keys[s] == k {
				t.Entries[s] = [2]uint64{}
				t.keys[s] = PageKey{}
			}
		}
	}
}

// HPTERead returns the doublewords in a slot.
func (m *Machine) HPTERead(slot uint64) (dw0, dw1 uint64, err error) {
	if m.HTAB == nil || slot >= uint64(len(m.HTAB.Entries)) {
		return 0, 0, fmt.Errorf("power: no hashed page table slot %d", slot)
	}
	e := m.HTAB.Entries[slot]
	return e[0], e[1], nil
}

// HPTEWrite replaces a slot. A valid entry's translation is installed (its H
// bit must match the group the slot is in, which is the caller's choice);
// the previous occupant's translation is removed.
func (m *Machine) HPTEWrite(slot, dw0, dw1 uint64) error {
	if m.HTAB == nil || slot >= uint64(len(m.HTAB.Entries)) {
		return fmt.Errorf("power: no hashed page table slot %d", slot)
	}
	t := m.HTAB
	if old := t.Entries[slot]; old[0]&hpteValid != 0 && dw0&hpteValid != 0 {
		// Software bits or newly set reference/change bits leave every
		// cached translation (which may name this slot) correct.
		if k, p, err := t.decodeEntry(slot, dw0, dw1); err == nil && k == t.keys[slot] && p == m.HPT[k] &&
			old[1]&^dw1&0x180 == 0 && old[1]&hpteTagSet == dw1&hpteTagSet {
			if s, ok := m.HPTESlot(k); ok && s == slot {
				t.Entries[slot] = [2]uint64{dw0, dw1}
				return nil
			}
		}
	}
	if old := t.Entries[slot]; old[0]&hpteValid != 0 {
		// Cached translations through this slot are discarded.
		oldKey := t.keys[slot]
		t.Entries[slot] = [2]uint64{}
		t.keys[slot] = PageKey{}
		m.refreshHPTE(oldKey)
		m.slotVer[slot]++
	}
	t.Entries[slot] = [2]uint64{dw0, dw1}
	if dw0&hpteValid == 0 {
		return nil
	}
	k, p, err := t.decodeEntry(slot, dw0, dw1)
	if err != nil {
		t.Entries[slot] = [2]uint64{}
		return err
	}
	if _, duplicate := m.HPT[k]; duplicate {
		// The page's effective entry may move to this slot, so discard
		// translations through the slot that was effective.
		if prev, ok := m.HPTESlot(k); ok {
			m.slotVer[prev]++
		} else {
			m.hptGen++
		}
		t.keys[slot] = k
		m.refreshHPTE(k)
	} else {
		t.keys[slot] = k
		// A new translation cannot contradict a cached one: caches only
		// hold successful translations, and a miss is not cached.
		m.HPT[k] = p
	}
	return nil
}

// refreshHPTE keeps effective translation and slot lookup on the same
// primary/secondary entry when multiple valid slots name one virtual page.
func (m *Machine) refreshHPTE(k PageKey) {
	slot, ok := m.HPTESlot(k)
	if !ok {
		delete(m.HPT, k)
		return
	}
	words := m.HTAB.Entries[slot]
	_, p, _ := m.HTAB.decodeEntry(slot, words[0], words[1])
	m.HPT[k] = p
}

// HPTESlot returns the slot holding a virtual page's valid entry.
func (m *Machine) HPTESlot(k PageKey) (uint64, bool) {
	if m.HTAB == nil {
		return 0, false
	}
	t := m.HTAB
	for _, secondary := range []bool{false, true} {
		g := t.Group(k.VSID, k.B, uint(k.Shift), k.Page, secondary)
		for i := uint64(0); i < 8; i++ {
			s := g*8 + i
			if t.Entries[s][0]&hpteValid != 0 && t.keys[s] == k {
				return s, true
			}
		}
	}
	return 0, false
}

func (t *HashedPageTable) clone() *HashedPageTable {
	if t == nil {
		return nil
	}
	return &HashedPageTable{Groups: t.Groups, Entries: slices.Clone(t.Entries), keys: slices.Clone(t.keys)}
}
