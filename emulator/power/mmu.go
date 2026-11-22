package power

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"unsafe"
)

// PageKey identifies one virtual page in the hashed page table: the segment's
// VSID, segment size and page size, and the page number within the segment.
type PageKey struct {
	VSID  uint64
	B     uint8
	Shift uint8
	Page  uint64
}

// PTE is a host-maintained page table entry.
type PTE struct {
	Real    uint64 // real address of the page
	Write   bool
	Execute bool
	Key     uint8 // protection key (PP bits); recorded, not enforced beyond Write
}

const (
	accessRead  = 1
	accessWrite = 2
	accessExec  = 4
)

// MapPage enters a page into the partition page table. va is the offset within
// the segment; it and real must be aligned to 1<<shift.
func (m *Machine) MapPage(vsid uint64, b uint8, offset uint64, shift uint, pte PTE) error {
	if shift != 12 && shift != 16 && shift != 24 && shift != 34 {
		return fmt.Errorf("power: page shift must be 12, 16, 24 or 34")
	}
	seg := uint(28)
	if b == 1 {
		seg = 40
	}
	if offset&(1<<shift-1) != 0 || pte.Real&(1<<shift-1) != 0 || offset>>seg != 0 || shift > seg {
		return fmt.Errorf("power: misaligned page or offset outside segment")
	}
	k := PageKey{VSID: vsid, B: b, Shift: uint8(shift), Page: offset >> shift}
	_, replaced := m.HPT[k]
	if m.HTAB != nil {
		m.htabRemoveKey(k)
		if err := m.htabPlace(k, pte); err != nil {
			return err
		}
	}
	m.HPT[k] = pte
	if replaced {
		// Only a replaced translation can be cached; misses are not.
		m.hptGen++
	}
	return nil
}

// UnmapPage removes a page; it reports whether one was present.
func (m *Machine) UnmapPage(vsid uint64, b uint8, offset uint64, shift uint) bool {
	k := PageKey{VSID: vsid, B: b, Shift: uint8(shift), Page: offset >> shift}
	_, ok := m.HPT[k]
	delete(m.HPT, k)
	if m.HTAB != nil {
		m.htabRemoveKey(k)
	}
	if ok {
		m.hptGen++
	}
	return ok
}

// LookupPage returns the entry covering a segment offset for the given page size.
func (m *Machine) LookupPage(vsid uint64, b uint8, offset uint64, shift uint) (PTE, bool) {
	p, ok := m.HPT[PageKey{VSID: vsid, B: b, Shift: uint8(shift), Page: offset >> shift}]
	return p, ok
}

// FindSLB returns the SLB entry translating ea.
func (c *CPU) FindSLB(ea uint64) (SLBEntry, bool) {
	// The last match is a search hint; any valid matching entry is correct.
	if e := &c.SLB[c.slbHint&63]; e.Valid && e.ESID == ea>>e.segmentShift() {
		return *e, true
	}
	for v := c.slbValid; v != 0; v &= v - 1 {
		i := bits.TrailingZeros64(v)
		if e := &c.SLB[i]; e.ESID == ea>>e.segmentShift() {
			c.slbHint = uint8(i)
			return *e, true
		}
	}
	return SLBEntry{}, false
}

// setSLB stores SLB entry i, keeping the valid-entry mask FindSLB scans.
func (c *CPU) setSLB(i int, e SLBEntry) {
	c.SLB[i] = e
	if e.Valid {
		c.slbValid |= 1 << i
	} else {
		c.slbValid &^= 1 << i
	}
}

// TranslateError describes why an effective address could not be translated.
type TranslateError struct {
	EA      uint64
	Segment bool // no SLB entry
	Protect bool // entry present but access denied
}

func (e *TranslateError) Error() string {
	switch {
	case e.Segment:
		return fmt.Sprintf("no segment for %016x", e.EA)
	case e.Protect:
		return fmt.Sprintf("protection fault at %016x", e.EA)
	}
	return fmt.Sprintf("no page table entry for %016x", e.EA)
}

// Translate maps an effective address under the CPU's current state without
// raising interrupts. instruction selects MSR[IR] instead of MSR[DR].
func (c *CPU) Translate(ea uint64, instruction bool, access int) (uint64, error) {
	r, _, _, _, err := c.translateEA(ea, instruction, access)
	return r, err
}

// translateEA is Translate, also reporting whether the mapping permits
// stores and, for a hashed page table translation, the page's key.
func (c *CPU) translateEA(ea uint64, instruction bool, access int) (real uint64, writable bool, key PageKey, paged bool, err error) {
	ea = c.mask(ea)
	bit := MSRDR
	if instruction {
		bit = MSRIR
	}
	if c.MSR&bit == 0 {
		return ea & (1<<60 - 1), true, PageKey{}, false, nil
	}
	if real, found, err := c.translateWindow(ea, access); found {
		writable := err == nil && (access&accessWrite != 0 || c.windowWritable(ea))
		return real, writable, PageKey{}, false, err
	}
	e, ok := c.segment(ea)
	if !ok {
		return 0, false, PageKey{}, false, &TranslateError{EA: ea, Segment: true}
	}
	shift := e.PageShift()
	off := ea & (1<<e.segmentShift() - 1)
	key = PageKey{VSID: e.VSID, B: e.B, Shift: uint8(shift), Page: off >> shift}
	p, ok := c.m.HPT[key]
	if !ok {
		return 0, false, PageKey{}, false, &TranslateError{EA: ea}
	}
	if access&accessWrite != 0 && !p.Write || access&accessExec != 0 && !p.Execute {
		return 0, false, PageKey{}, false, &TranslateError{EA: ea, Protect: true}
	}
	return p.Real | off&(1<<shift-1), p.Write, key, true, nil
}

func (c *CPU) windowWritable(ea uint64) bool {
	_, _, err := c.translateWindow(ea, accessWrite)
	return err == nil
}

// slotCurrent reports whether a cached translation through HPTE slot+1 is
// still current (slot 0 names no table slot).
func (m *Machine) slotCurrent(slot uint64, ver uint32) bool {
	return slot == 0 || m.slotVer[slot-1] == ver
}

// jitZeroVersion is the version word of translations without a table slot.
var jitZeroVersion uint32

// slotVersionAddress locates slot+1's version word. Native code reads it
// only after checking the entry's generation, which changes whenever the
// version array is replaced.
func (m *Machine) slotVersionAddress(slot uint64) uintptr {
	if slot == 0 {
		return uintptr(unsafe.Pointer(&jitZeroVersion))
	}
	return uintptr(unsafe.Pointer(&m.slotVer[slot-1]))
}

func (m *Machine) slotVersion(slot uint64) uint32 {
	if slot == 0 {
		return 0
	}
	return m.slotVer[slot-1]
}

// tlbSize is the number of entries in each direct-mapped translation cache.
const tlbSize = 1 << tlbBits

// tlbIndex hashes the whole page number, so pages at equal offsets in
// different segments (single-level-store objects differ in high effective
// address bits) do not collide, and MSR[PR], part of the tag, so a page's
// problem- and privileged-state translations do not evict each other.
func (c *CPU) tlbIndex(ea uint64) uint64 {
	return ((ea>>12)<<1 | c.MSR>>MSRPRShift&1) * tlbHash >> (64 - tlbBits)
}

const (
	tlbBits = 14
	tlbHash = 0x9e3779b97f4a7c15
)

// tlbTag identifies a cached translation: the effective page, MSR[PR]
// (translation windows check user access) and the access kind, with the low
// bit set so a zero tag is invalid. Translation does not otherwise depend on
// the MSR, so relocation and state changes need not flush the caches.
func (c *CPU) tlbTag(ea uint64, instruction bool) uint64 {
	tag := (ea>>12)<<3 | (c.MSR>>MSRPRShift&1)<<2 | 1
	if instruction {
		tag |= 2
	}
	return tag
}

// translate maps ea for an access, raising the architected interrupt on failure.
func (c *CPU) translate(ea uint64, access int) (uint64, bool) {
	ea = c.mask(ea)
	instruction := access == accessExec
	bit := MSRDR
	if instruction {
		bit = MSRIR
	}
	if c.MSR&bit == 0 {
		return c.real(ea&(1<<60-1), 1)
	}
	tag := c.tlbTag(ea, instruction)
	t := &c.tlb[c.tlbIndex(ea)]
	if instruction {
		t = &c.itlb[c.tlbIndex(ea)]
	}
	if t.tag == tag && t.gen == c.tlbGen^c.m.hptGen<<32 && t.ok&uint8(access) != 0 && c.m.slotCurrent(t.slot, t.slotVer) {
		// Reference and change bits were set when the entry was filled
		// for this access kind; clearing them changes hptGen.
		return t.real | ea&0xfff, true
	}
	r, writable, key, paged, err := c.translateEA(ea, instruction, access)
	if err != nil {
		te := err.(*TranslateError)
		switch {
		case instruction && te.Segment:
			c.Interrupt(VecInstrSegment, c.PC, 0)
		case instruction:
			reason := uint64(0x40000000)
			if te.Protect {
				reason = 0x08000000
			}
			c.Interrupt(VecInstrStorage, c.PC, reason)
		case te.Segment:
			c.DAR = ea
			c.Interrupt(VecDataSegment, c.PC, 0)
		default:
			c.DAR = ea
			c.DSISR = 0x40000000
			if te.Protect {
				c.DSISR = 0x08000000
			}
			if access == accessWrite {
				c.DSISR |= 0x02000000
			}
			c.Interrupt(VecDataStorage, c.PC, 0)
		}
		return 0, false
	}
	ok := uint8(access)
	if access == accessWrite {
		// A successful store also establishes read permission.
		ok |= accessRead
	}
	slot := uint64(0)
	cacheable := r&^0xfff+0x1000 <= uint64(len(c.m.Mem))
	if c.m.HTAB != nil && paged {
		if index, found := c.m.HPTESlot(key); found {
			slot = index + 1
		} else {
			cacheable = false // only slot versions guard table translations
		}
	}
	if access == accessRead && writable && (slot == 0 || c.m.HTAB.Entries[slot-1][1]&0x80 != 0) {
		// Stores to a writable page whose change bit is already set need
		// no further page-table update, so the read fill admits them too.
		ok |= accessWrite
	}
	if cacheable {
		// Only pages wholly inside real memory are cached, so cached
		// accesses need no further bounds check.
		*t = tlbEntry{tag: tag, gen: c.tlbGen ^ c.m.hptGen<<32, real: r &^ 0xfff, slot: slot, verPtr: c.m.slotVersionAddress(slot),
			slotVer: c.m.slotVersion(slot), ok: ok}
	}
	c.referenceHPTE(slot, access)
	return c.real(r, 1)
}

// Successful CPU accesses set the architected reference bit, and stores also
// set change. Debugger/backend Translate and ReadEffective calls do not.
// Keep the slot in the TLB so a load followed by a cached store still sets C.
func (c *CPU) referenceHPTE(slot uint64, access int) {
	if slot != 0 {
		bits := uint64(0x100)
		if access&accessWrite != 0 {
			bits |= 0x80
		}
		c.m.HTAB.Entries[slot-1][1] |= bits
	}
}

func (c *CPU) real(r uint64, n int) (uint64, bool) {
	if r+uint64(n) > uint64(len(c.m.Mem)) || r+uint64(n) < r {
		c.Stop("machine-check", fmt.Sprintf("real address %x outside %d-byte memory at pc %016x", r, len(c.m.Mem), c.PC))
		c.fault = true
		return 0, false
	}
	return r, true
}

// Load reads n (1, 2, 4, 8) bytes big-endian at ea, raising interrupts.
func (c *CPU) Load(ea uint64, n int) (uint64, bool) {
	ea = c.mask(ea)
	if c.MSR&MSRDR != 0 && ea&0xfff <= 0x1000-uint64(n) {
		t := &c.tlb[c.tlbIndex(ea)]
		if t.tag == c.tlbTag(ea, false) && t.gen == c.tlbGen^c.m.hptGen<<32 && t.ok&accessRead != 0 && c.m.slotCurrent(t.slot, t.slotVer) {
			return loadBE(c.m.Mem[t.real|ea&0xfff:], n), true
		}
	} else if c.MSR&MSRDR == 0 && ea < uint64(len(c.m.Mem)) && uint64(len(c.m.Mem))-ea >= uint64(n) {
		return loadBE(c.m.Mem[ea:], n), true
	}
	return c.loadSlow(ea, n)
}

func loadBE(mem []byte, n int) uint64 {
	switch n {
	case 1:
		return uint64(mem[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(mem))
	case 4:
		return uint64(binary.BigEndian.Uint32(mem))
	}
	return binary.BigEndian.Uint64(mem)
}

func storeBE(mem []byte, n int, v uint64) {
	switch n {
	case 1:
		mem[0] = byte(v)
	case 2:
		binary.BigEndian.PutUint16(mem, uint16(v))
	case 4:
		binary.BigEndian.PutUint32(mem, uint32(v))
	default:
		binary.BigEndian.PutUint64(mem, v)
	}
}

func (c *CPU) loadSlow(ea uint64, n int) (uint64, bool) {
	if ea&0xfff+uint64(n) > 0x1000 {
		var v uint64
		for i := 0; i < n; i++ {
			b, ok := c.Load(ea+uint64(i), 1)
			if !ok {
				return 0, false
			}
			v = v<<8 | b
		}
		return v, true
	}
	r, ok := c.translate(ea, accessRead)
	if !ok {
		return 0, false
	}
	if _, ok := c.real(r, n); !ok {
		return 0, false
	}
	return loadBE(c.m.Mem[r:], n), true
}

// Store writes n bytes big-endian at ea, raising interrupts.
func (c *CPU) Store(ea uint64, n int, v uint64) bool {
	ea = c.mask(ea)
	if c.MSR&MSRDR != 0 && ea&0xfff <= 0x1000-uint64(n) {
		t := &c.tlb[c.tlbIndex(ea)]
		if t.tag == c.tlbTag(ea, false) && t.gen == c.tlbGen^c.m.hptGen<<32 && t.ok&accessWrite != 0 && c.m.slotCurrent(t.slot, t.slotVer) {
			r := t.real | ea&0xfff
			storeBE(c.m.Mem[r:], n, v)
			c.m.stored(c, r, n)
			return true
		}
	} else if c.MSR&MSRDR == 0 && ea < uint64(len(c.m.Mem)) && uint64(len(c.m.Mem))-ea >= uint64(n) {
		storeBE(c.m.Mem[ea:], n, v)
		c.m.stored(c, ea, n)
		return true
	}
	return c.storeSlow(ea, n, v)
}

func (c *CPU) storeSlow(ea uint64, n int, v uint64) bool {
	if ea&0xfff+uint64(n) > 0x1000 {
		// Translate both pages before writing any byte.
		if _, ok := c.translate(ea, accessWrite); !ok {
			return false
		}
		if _, ok := c.translate(ea+uint64(n)-1, accessWrite); !ok {
			return false
		}
		for i := 0; i < n; i++ {
			if !c.Store(ea+uint64(i), 1, v>>(8*(n-1-i))) {
				return false
			}
		}
		return true
	}
	r, ok := c.translate(ea, accessWrite)
	if !ok {
		return false
	}
	if _, ok := c.real(r, n); !ok {
		return false
	}
	storeBE(c.m.Mem[r:], n, v)
	c.m.stored(c, r, n)
	return true
}

// ReadEffective copies memory through the current translation without
// raising interrupts.
func (c *CPU) ReadEffective(ea uint64, n int) ([]byte, error) {
	out := make([]byte, 0, n)
	for n > 0 {
		r, err := c.Translate(ea, false, accessRead)
		if err != nil {
			return nil, err
		}
		chunk := min(n, int(0x1000-ea&0xfff))
		if r+uint64(chunk) > uint64(len(c.m.Mem)) {
			return nil, fmt.Errorf("real address %x outside memory", r)
		}
		out = append(out, c.m.Mem[r:r+uint64(chunk)]...)
		ea += uint64(chunk)
		n -= chunk
	}
	return out, nil
}

// WriteEffective copies data through the current translation without
// raising interrupts or checking page protection.
func (c *CPU) WriteEffective(ea uint64, data []byte) error {
	for len(data) > 0 {
		r, err := c.Translate(ea, false, accessRead)
		if err != nil {
			return err
		}
		chunk := min(len(data), int(0x1000-ea&0xfff))
		if r+uint64(chunk) > uint64(len(c.m.Mem)) {
			return fmt.Errorf("real address %x outside memory", r)
		}
		copy(c.m.Mem[r:], data[:chunk])
		c.m.stored(c, r, chunk)
		ea += uint64(chunk)
		data = data[chunk:]
	}
	return nil
}

func (c *CPU) fetch() (uint32, bool) {
	ea := c.mask(c.PC)
	if c.fetchKey(ea) == c.fetchPage && c.fetchGen == c.tlbGen^c.m.hptGen<<32 && c.m.slotCurrent(c.fetchSlot, c.fetchSlotVer) {
		return binary.BigEndian.Uint32(c.m.Mem[c.fetchReal|ea&0xfff:]), true
	}
	return c.fetchSlow(ea)
}

// fetchKey names an instruction page under MSR[IR] and MSR[PR].
func (c *CPU) fetchKey(ea uint64) uint64 {
	return (ea>>12)<<3 | (c.MSR>>MSRPRShift&1)<<2 | (c.MSR>>MSRIRShift&1)<<1 | 1
}

// fetchSlow translates a new instruction page. The cache holds only the
// translation, so writes to executable memory are immediately visible.
func (c *CPU) fetchSlow(ea uint64) (uint32, bool) {
	r := ea & (1<<60 - 1)
	slot, cache := uint64(0), true
	if c.MSR&MSRIR != 0 {
		var ok bool
		if r, ok = c.translate(ea, accessExec); !ok {
			return 0, false
		}
		// Cache the page only when its translation was cached, so the
		// fetch cache has the instruction TLB's validity.
		t := &c.itlb[c.tlbIndex(ea)]
		cache = t.tag == c.tlbTag(ea, true) && t.gen == c.tlbGen^c.m.hptGen<<32
		slot = t.slot
	}
	if r >= uint64(len(c.m.Mem)) || uint64(len(c.m.Mem))-r < 4 {
		c.real(r, 4)
		return 0, false
	}
	if cache && r&^0xfff+0x1000 <= uint64(len(c.m.Mem)) {
		c.fetchPage, c.fetchReal, c.fetchGen = c.fetchKey(ea), r&^0xfff, c.tlbGen^c.m.hptGen<<32
		c.fetchSlot, c.fetchSlotVer = slot, c.m.slotVersion(slot)
	}
	return binary.BigEndian.Uint32(c.m.Mem[r : r+4]), true
}

// SegmentRange is a range of 256 MiB effective segment IDs [First, End).
type SegmentRange struct {
	First, End uint64
}

// SetIdentitySegments leaves misses in guest-managed ranges to the guest's
// segment interrupt handlers. Discard only previously synthesized entries.
func (m *Machine) SetIdentitySegments(enabled bool, guest []SegmentRange) error {
	for _, r := range guest {
		if r.First >= r.End || r.End > 1<<36 {
			return fmt.Errorf("power: invalid guest segment range [%x,%x)", r.First, r.End)
		}
	}
	m.IdentitySegments = enabled
	m.guestSegments = append([]SegmentRange(nil), guest...)
	for _, c := range m.CPUs {
		for i, e := range c.SLB {
			if e.implicit {
				c.setSLB(i, SLBEntry{})
			}
		}
		c.tlbGen++
	}
	return nil
}

func (m *Machine) useIdentitySegment(ea uint64) bool {
	if !m.IdentitySegments {
		return false
	}
	esid := ea >> 28
	for _, r := range m.guestSegments {
		if esid >= r.First && esid < r.End {
			return false
		}
	}
	return true
}

// segment returns the SLB entry translating ea: a matching SLB entry, else
// under Machine.IdentitySegments the identity segment for ea, which is not
// stored. Identity segments are a host policy rather than architected SLB
// contents, so slbmfee and the state digest see the same SLB whether or
// not native code skipped a translation.
func (c *CPU) segment(ea uint64) (SLBEntry, bool) {
	if e, ok := c.FindSLB(ea); ok {
		return e, true
	}
	if c.m.useIdentitySegment(ea) {
		return SLBEntry{Valid: true, implicit: true, ESID: ea >> 28, VSID: ea >> 28}, true
	}
	return SLBEntry{}, false
}

// identitySegment resolves a segment miss under Machine.IdentitySegments:
// a 256MB segment whose VSID equals its ESID (so the virtual address equals
// the effective address), 4KB base pages, loaded round-robin into the upper
// half of the SLB so guest-managed low indices are not displaced.
func (c *CPU) identitySegment(ea uint64) SLBEntry {
	e := SLBEntry{Valid: true, implicit: true, ESID: ea >> 28, VSID: ea >> 28}
	half := uint64(len(c.SLB) / 2)
	c.setSLB(int(half+c.slbNext%half), e)
	c.slbNext++
	return e
}

// SLBMTE performs slbmte with the given RS and RB operands.
func (c *CPU) SLBMTE(rs, rb uint64) error {
	idx := rb & 0xfff
	if idx >= uint64(len(c.SLB)) {
		return fmt.Errorf("power: SLB index %d out of range", idx)
	}
	e := SLBEntry{Valid: rb&(1<<27) != 0, B: uint8(rs >> 62), VSID: rs >> 12 & (1<<50 - 1), Flags: rs & 0xfff}
	e.ESID = rb >> 28 >> (e.segmentShift() - 28)
	c.setSLB(int(idx), e)
	c.tlbGen++
	return nil
}

// HPTESlot returns the slot of the page translating ea under the current
// SLB (or identity segment). It does not populate the SLB or change memory.
// ok is false if there is no matching segment or valid slot-addressed table
// entry.
func (c *CPU) HPTESlot(ea uint64) (uint64, bool) {
	e, found := c.segment(c.mask(ea))
	if !found {
		return 0, false
	}
	shift := e.PageShift()
	off := ea & (1<<e.segmentShift() - 1)
	return c.m.HPTESlot(PageKey{VSID: e.VSID, B: e.B, Shift: uint8(shift), Page: off >> shift})
}

// HPTE returns the architected entry doublewords for the page translating ea
// under the CPU's current SLB and host page table. ok is false if unmapped.
func (c *CPU) HPTE(ea uint64) (dw0, dw1 uint64, ok bool) {
	e, found := c.segment(c.mask(ea))
	if !found {
		return 0, 0, false
	}
	shift := e.PageShift()
	off := ea & (1<<e.segmentShift() - 1)
	p, found := c.m.LookupPage(e.VSID, e.B, off, shift)
	if !found {
		return 0, 0, false
	}
	if slot, ok := c.m.HPTESlot(PageKey{VSID: e.VSID, B: e.B, Shift: uint8(shift), Page: off >> shift}); ok {
		w := c.m.HTAB.Entries[slot]
		return w[0], w[1], true
	}
	dw0, dw1 = pteWords(PageKey{VSID: e.VSID, B: e.B, Shift: uint8(shift), Page: off >> shift}, p, false)
	return dw0, dw1, true
}
