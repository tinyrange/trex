package arm64

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/emulator/cpu"
)

// TranslationFault reports the architectural fault status without pretending
// that the exception handler has run. An execution controller may inspect it.
type TranslationFault struct {
	Address uint64
	Status  uint64
}

func (e *TranslationFault) Error() string {
	return fmt.Sprintf("arm64: translation fault %#x at VA %#x", e.Status, e.Address)
}

// Translate implements stage-1 EL1/EL0 4-KiB translation tables, including
// block/page descriptors, access flags and hierarchical permissions.
func (c *CPU) Translate(m cpu.Memory, address uint64, access cpu.Access) (uint64, error) {
	pa, _, err := c.translate(m, address, access)
	return pa, err
}
func (c *CPU) translate(m cpu.Memory, address uint64, access cpu.Access) (uint64, uint64, error) {
	if c.system[0]&1 != 0 && !c.DisableTranslationCache {
		if ram, ok := m.(*cpu.AddressSpace); ok {
			return c.cachedTranslate(ram, address, access)
		}
	}
	return c.walk(m, address, access)
}

func (c *CPU) walk(m cpu.Memory, address uint64, access cpu.Access) (uint64, uint64, error) {
	if c.system[0]&1 == 0 {
		return address, 0xff00000000000800, nil
	}
	if c.currentEL > 4 {
		return 0, 0, fmt.Errorf("arm64: EL2/EL3 translation is not implemented")
	}
	tcr := c.system[3]
	upper := address>>55&1 != 0
	va := address
	size := uint32(tcr & 63)
	ttbr := c.system[1]
	disabled := tcr>>7&1 != 0
	granule := tcr >> 14 & 3
	if upper {
		size = uint32(tcr >> 16 & 63)
		ttbr = c.system[2]
		disabled = tcr>>23&1 != 0
		granule = tcr >> 30 & 3
		if granule == 2 {
			granule = 0
		} else {
			granule = 3
		}
		if tcr>>38&1 != 0 {
			va |= 0xff00000000000000
		}
	} else if tcr>>37&1 != 0 {
		va &= 0x00ffffffffffffff
	}
	if granule != 0 {
		return 0, 0, fmt.Errorf("arm64: only 4 KiB translation granules are implemented")
	}
	if size < 16 || size > 39 {
		return 0, 0, fmt.Errorf("arm64: unsupported TCR address size %d", size)
	}
	bits := 64 - size
	high := va >> bits
	expected := uint64(0)
	if upper {
		expected = mask(size)
	}
	if high != expected {
		return 0, 0, &TranslationFault{address, 0}
	}
	level := uint32(4) - (bits-12+8)/9
	if disabled {
		return 0, 0, &TranslationFault{address, 4 + uint64(level)}
	}
	table := ttbr & 0x0000fffffffff000
	readOnly, userDenied, pxn, uxn := false, false, false, false
	for ; level <= 3; level++ {
		shift := uint32(12 + 9*(3-level))
		index := va >> shift & 511
		if ram, ok := m.(*cpu.AddressSpace); ok && !c.DisableTranslationCache {
			ram.TrackPageWrites(table + index*8)
		}
		d, err := readDescriptor(m, table+index*8)
		if err != nil {
			return 0, 0, fmt.Errorf("arm64: translation table read: %w", err)
		}
		kind := d & 3
		if kind == 0 || kind == 2 || level == 0 && kind == 1 || level == 3 && kind != 3 {
			return 0, 0, &TranslationFault{address, 4 + uint64(level)}
		}
		if kind == 3 && level < 3 {
			table = d & 0x0000fffffffff000
			readOnly = readOnly || d>>62&1 != 0
			userDenied = userDenied || d>>61&1 != 0
			pxn = pxn || d>>59&1 != 0
			uxn = uxn || d>>60&1 != 0
			continue
		}
		if d>>10&1 == 0 {
			return 0, 0, &TranslationFault{address, 8 + uint64(level)}
		}
		ap := d >> 6 & 3
		user := c.currentEL == 0
		if access&cpu.Write != 0 && (readOnly || ap&2 != 0) || user && (userDenied || ap&1 == 0) || access&cpu.Execute != 0 && (!user && (pxn || d>>53&1 != 0) || user && (uxn || d>>54&1 != 0)) {
			return 0, 0, &TranslationFault{address, 12 + uint64(level)}
		}
		physical := (d&0x0000fffffffff000)&^mask(shift) | va&mask(shift)
		attribute := c.system[4] >> ((d >> 2 & 7) * 8) & 255
		return physical, attribute<<56 | uint64(1)<<11 | d>>8&3<<7 | uint64(1)<<9, nil
	}
	return 0, 0, &TranslationFault{address, 7}
}

// A concrete address-space read keeps the descriptor buffer on the stack.
// Observing/device memory still receives every read through its own interface.
func readDescriptor(m cpu.Memory, address uint64) (uint64, error) {
	if ram, ok := m.(*cpu.AddressSpace); ok {
		var b [8]byte
		err := ram.ReadMemory(address, b[:], cpu.Read)
		return binary.LittleEndian.Uint64(b[:]), err
	}
	var b [8]byte
	err := m.ReadMemory(address, b[:], cpu.Read)
	return binary.LittleEndian.Uint64(b[:]), err
}

// VirtualMemory adapts caller-owned physical memory to the active CPU tables.
// It checks an entire access before copying, including page-crossing writes.
func (c *CPU) VirtualMemory(m cpu.Memory) cpu.Memory {
	var virtual cpu.Memory = m
	if c.system[0]&1 != 0 {
		virtual = translatedMemory{c, m}
	}
	if c.exclusiveValid {
		return exclusiveMemory{c, virtual, m}
	}
	return virtual
}

type translatedMemory struct {
	c        *CPU
	physical cpu.Memory
}
type span struct {
	address uint64
	size    int
}

func (m translatedMemory) spans(a uint64, n int, access cpu.Access) ([]span, error) {
	if n < 0 || uint64(n) > ^uint64(0)-a {
		return nil, fmt.Errorf("arm64: overflowing virtual access")
	}
	var spans []span
	for n > 0 {
		size := min(n, 4096-int(a&4095))
		pa, err := m.c.Translate(m.physical, a, access)
		if err != nil {
			return nil, err
		}
		if err := m.physical.CheckMemory(pa, size, access); err != nil {
			return nil, err
		}
		spans = append(spans, span{pa, size})
		a += uint64(size)
		n -= size
	}
	return spans, nil
}
func (m translatedMemory) CheckMemory(a uint64, n int, access cpu.Access) error {
	if n > 0 && n <= 4096-int(a&4095) && uint64(n) <= ^uint64(0)-a {
		pa, err := m.c.Translate(m.physical, a, access)
		if err != nil {
			return err
		}
		return m.physical.CheckMemory(pa, n, access)
	}
	_, err := m.spans(a, n, access)
	return err
}
func (m translatedMemory) ReadMemory(a uint64, b []byte, access cpu.Access) error {
	if len(b) > 0 && len(b) <= 4096-int(a&4095) && uint64(len(b)) <= ^uint64(0)-a {
		pa, err := m.c.Translate(m.physical, a, access)
		if err != nil {
			return err
		}
		return m.physical.ReadMemory(pa, b, access)
	}
	spans, err := m.spans(a, len(b), access)
	if err != nil {
		return err
	}
	for _, s := range spans {
		if err := m.physical.ReadMemory(s.address, b[:s.size], access); err != nil {
			return err
		}
		b = b[s.size:]
	}
	return nil
}
func (m translatedMemory) WriteMemory(a uint64, b []byte) error {
	if len(b) > 0 && len(b) <= 4096-int(a&4095) && uint64(len(b)) <= ^uint64(0)-a {
		pa, err := m.c.Translate(m.physical, a, cpu.Write)
		if err != nil {
			return err
		}
		return m.physical.WriteMemory(pa, b)
	}
	spans, err := m.spans(a, len(b), cpu.Write)
	if err != nil {
		return err
	}
	for _, s := range spans {
		if err := m.physical.WriteMemory(s.address, b[:s.size]); err != nil {
			return err
		}
		b = b[s.size:]
	}
	return nil
}
