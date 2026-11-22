package power

import (
	"fmt"
	"math/bits"
)

// PowerPC AS pointer tags (extension "as"). Each 16-byte quadword of real
// memory carries a hidden pointer tag. Ordinary stores clear it; lq reads
// it into XER[43], stq writes XER[43], and settag sets XER[43] to one.

// tagAt returns the tag of the quadword at an effective address (false if
// it does not translate).
func (m *Machine) tagAt(c *CPU, ea uint64) bool {
	r, err := c.Translate(c.mask(ea), false, accessRead)
	if err != nil || r >= uint64(len(m.Mem)) {
		return false
	}
	q := r >> 4
	return m.tags[q>>6]&(1<<(q&63)) != 0
}

// setTag completes a tagged stq. An aligned quadword is wholly within the
// data translation used by both stores. Book III (AS) §4.8 permits hardware
// to record these stores in the translating HPTE's sticky TS bit.
func (m *Machine) setTag(c *CPU, ea uint64) {
	ea = c.mask(ea)
	r, ok := c.translate(ea, accessWrite)
	if !ok {
		return
	}
	q := r >> 4
	m.tags[q>>6] |= 1 << (q & 63)
	if c.MSR&MSRDR != 0 {
		if slot := c.tlb[c.tlbIndex(ea)].slot; slot != 0 {
			m.HTAB.Entries[slot-1][1] |= hpteTagSet
		}
	}
}

// Tag reports the tag of the quadword at a real address.
func (m *Machine) Tag(real uint64) bool {
	if m.tags == nil || real >= uint64(len(m.Mem)) {
		return false
	}
	q := real >> 4
	return m.tags[q>>6]&(1<<(q&63)) != 0
}

// PointerTags inspects quadword tags without executing a load or changing CPU
// state. Bits are MSB-first in ascending 16-byte real-address order. The range
// must contain complete quadwords; the last bitmap byte is zero-padded.
func (m *Machine) PointerTags(real, length uint64) ([]byte, error) {
	if real&15 != 0 || length&15 != 0 || real > uint64(len(m.Mem)) || length > uint64(len(m.Mem))-real {
		return nil, fmt.Errorf("power: invalid pointer-tag range %x/%x", real, length)
	}
	quads := length / 16
	bits := make([]byte, (quads+7)/8)
	for i := uint64(0); i < quads; i++ {
		if m.Tag(real + i*16) {
			bits[i/8] |= 0x80 >> (i % 8)
		}
	}
	return bits, nil
}

// RestorePageTags sets the indicated tags on an aligned 4 KiB real page.
// The four words list quadwords in MSB-first address order. Unmarked
// quadwords are untouched. Restoring a tag has the effects of a tagged
// store of the original quadword, including watches and reservations.
func (c *CPU) RestorePageTags(page uint64, tags [4]uint64) error {
	m := c.m
	end := uint64(len(m.Mem))
	if page&4095 != 0 || page > end || 4096 > end-page || m.tags == nil {
		return fmt.Errorf("power: invalid AS pointer-tag page %x", page)
	}
	for i, word := range tags {
		start := page + uint64(i)*1024
		c.restoreSectorTags(start, uint32(word>>32))
		c.restoreSectorTags(start+512, uint32(word))
	}
	return nil
}

func (c *CPU) restoreSectorTags(sector uint64, tags uint32) {
	m := c.m
	for tags != 0 {
		q := uint64(bits.LeadingZeros32(tags))
		at := sector + q*16
		m.stored(c, at, 16)
		index := at / 16
		m.tags[index/64] |= 1 << (index % 64)
		tags &^= uint32(1) << (31 - q)
	}
}

// CopyRealPage copies one aligned 4KB real page including its quadword tags.
// Hypervisors use this to relocate guest pages without losing pointer tags.
// It has the same store-watch and reservation effects as a guest store.
func (c *CPU) CopyRealPage(dst, src uint64) error {
	m := c.m
	size := uint64(len(m.Mem))
	if dst&4095 != 0 || src&4095 != 0 || size < 4096 || dst > size-4096 || src > size-4096 {
		return fmt.Errorf("power: real page copy range %x/%x outside memory or unaligned", dst, src)
	}
	var tags [4]uint64
	if m.tags != nil {
		copy(tags[:], m.tags[src/1024:src/1024+4])
	}
	copy(m.Mem[dst:dst+4096], m.Mem[src:src+4096])
	m.stored(c, dst, 4096)
	if m.tags != nil {
		copy(m.tags[dst/1024:dst/1024+4], tags[:])
	}
	return nil
}

// CopyRealTagged follows a forward AS tag-preserving byte copy. Source and
// destination must have the same quadword alignment. Complete aligned
// quadwords carry tags; partial leading/trailing stores clear destination
// tags. All bounds are checked before mutation. Overlap follows forward
// quadword loads/stores rather than an implicit memmove of the entire range.
func (c *CPU) CopyRealTagged(dst, src, length uint64) error {
	m := c.m
	size := uint64(len(m.Mem))
	if dst > size || src > size || length > size-dst || length > size-src || length != 0 && (dst^src)&15 != 0 {
		return fmt.Errorf("power: tagged real copy range/alignment %x/%x/%x", dst, src, length)
	}
	if length == 0 {
		return nil
	}
	partial := func(n uint64) {
		var data [16]byte
		copy(data[:], m.Mem[src:src+n])
		copy(m.Mem[dst:dst+n], data[:n])
		m.stored(c, dst, int(n))
		dst += n
		src += n
		length -= n
	}
	if src&15 != 0 {
		partial(min(length, 16-src%16))
	}
	for length >= 16 {
		if (dst|src)&4095 == 0 && length >= 4096 {
			if err := c.CopyRealPage(dst, src); err != nil {
				return err
			}
			dst += 4096
			src += 4096
			length -= 4096
			continue
		}
		tag := m.Tag(src)
		partial(16)
		if tag && m.tags != nil {
			q := (dst - 16) >> 4
			m.tags[q>>6] |= 1 << (q & 63)
		}
	}
	if length != 0 {
		partial(length)
	}
	return nil
}
