package cc

import (
	"fmt"
	"math"
	"time"

	"j5.nz/cc/hypervisor"
)

const hpetAddress = 0xfed00000
const hpetCapabilities uint64 = 10000000<<32 | 0x8086<<16 | 1<<13 | 2<<8 | 1
const hpetTimerCapabilities uint64 = 0x00f00000<<32 | 1<<5 | 1<<4

// hpet implements three 64-bit comparators at 100 MHz. Interrupts use the
// IOAPIC; legacy replacement and FSB delivery are not advertised.
// Register semantics follow Intel HPET specification 1.0a.
type hpet struct {
	config, status uint64
	base           uint64
	started        time.Time
	timers         [3]hpetTimer
	setIRQ         func(uint32, bool) error
}
type hpetTimer struct {
	config, match, period uint64
	next                  time.Time
	asserted              bool
}

func newHPET(now time.Time, setIRQ func(uint32, bool) error) *hpet {
	h := &hpet{started: now, setIRQ: setIRQ}
	for i := range h.timers {
		h.timers[i].match = ^uint64(0)
	}
	return h
}
func (h *hpet) counter(now time.Time) uint64 {
	if h.config&1 == 0 {
		return h.base
	}
	d := now.Sub(h.started)
	if d < 0 {
		d = 0
	}
	return h.base + uint64(d/(10*time.Nanosecond))
}
func (h *hpet) arm(i int, now time.Time) { h.armAfter(i, now, false) }
func (h *hpet) armAfter(i int, now time.Time, afterMatch bool) {
	t := &h.timers[i]
	t.next = time.Time{}
	if h.config&1 == 0 {
		return
	}
	counter := h.counter(now)
	delta := t.match - counter
	if t.config&(1<<8) != 0 {
		delta = uint64(uint32(delta))
		if afterMatch && delta == 0 {
			delta = 1 << 32
		}
		if t.config&8 == 0 {
			// In 32-bit one-shot mode HPET also interrupts on counter rollover.
			delta = min(delta, (1<<32)-uint64(uint32(counter)))
		}
	}
	if delta > uint64(math.MaxInt64/10) {
		return
	}
	t.next = now.Add(time.Duration(delta) * 10 * time.Nanosecond)
}
func (h *hpet) expire(i int, now time.Time) {
	t := &h.timers[i]
	if t.config&2 != 0 {
		h.status |= 1 << i
	}
	if t.config&4 != 0 && t.config&2 != 0 {
		t.asserted = true
	}
	if t.config&8 != 0 && t.period != 0 {
		steps := uint64(1)
		if !t.next.IsZero() && now.After(t.next) {
			steps += uint64(now.Sub(t.next)/(10*time.Nanosecond)) / t.period
		}
		t.match += steps * t.period
		if t.config&(1<<8) != 0 {
			t.match = uint64(uint32(t.match))
		}
		h.arm(i, now)
	} else {
		// A one-shot comparator can match again only after counter wrap.
		t.next = time.Time{}
		if t.config&(1<<8) != 0 {
			h.armAfter(i, now, true)
		}
	}
}
func (h *hpet) delivery(i int) func() error {
	t := h.timers[i]
	irq := uint32(t.config >> 9 & 31)
	shared := false
	for j, other := range h.timers {
		if j != i && other.asserted && uint32(other.config>>9&31) == irq {
			shared = true
		}
	}
	return func() error {
		if t.config&4 == 0 || t.asserted || shared {
			return nil
		}
		if err := h.setIRQ(irq, true); err != nil {
			return err
		}
		if t.config&2 == 0 {
			return h.setIRQ(irq, false)
		}
		return nil
	}
}
func (h *hpet) poll(now time.Time) error {
	for i := range h.timers {
		t := &h.timers[i]
		if !t.next.IsZero() && !now.Before(t.next) {
			if err := h.delivery(i)(); err != nil {
				return err
			}
			h.expire(i, now)
		}
	}
	return nil
}
func (h *hpet) deadline() (int, time.Time) {
	index := -1
	var next time.Time
	for i, t := range h.timers {
		if t.config&4 == 0 || t.asserted || t.next.IsZero() {
			continue
		}
		if next.IsZero() || t.next.Before(next) {
			index, next = i, t.next
		}
	}
	return index, next
}
func (h *hpet) read(reg uint64, now time.Time) uint64 {
	switch reg {
	case 0:
		return hpetCapabilities
	case 0x10:
		return h.config
	case 0x20:
		return h.status
	case 0xf0:
		return h.counter(now)
	}
	if reg >= 0x100 && reg < 0x160 {
		t := &h.timers[(reg-0x100)/0x20]
		switch reg & 0x1f {
		case 0:
			return t.config | hpetTimerCapabilities
		case 8:
			return t.match
		}
	}
	return 0
}
func (h *hpet) lower(i int) error {
	t := &h.timers[i]
	if !t.asserted {
		return nil
	}
	irq := uint32(t.config >> 9 & 31)
	for j, other := range h.timers {
		if j != i && other.asserted && uint32(other.config>>9&31) == irq {
			t.asserted = false
			return nil
		}
	}
	if err := h.setIRQ(irq, false); err != nil {
		return err
	}
	t.asserted = false
	return nil
}
func (h *hpet) write(reg, value, mask uint64, now time.Time) error {
	old := h.read(reg, now)
	merged := old&^mask | value&mask
	switch reg {
	case 0x10:
		h.base = h.counter(now)
		h.started = now
		h.config = merged & 1
		for i := range h.timers {
			h.arm(i, now)
		}
	case 0x20:
		for i := range h.timers {
			if value&mask&(1<<i) != 0 {
				h.status &^= 1 << i
				if err := h.lower(i); err != nil {
					return err
				}
			}
		}
	case 0xf0:
		h.base, h.started = merged, now
		for i := range h.timers {
			h.arm(i, now)
		}
	default:
		if reg < 0x100 || reg >= 0x160 {
			return nil
		}
		i := int((reg - 0x100) / 0x20)
		t := &h.timers[i]
		switch reg & 0x1f {
		case 0:
			if err := h.lower(i); err != nil {
				return err
			}
			t.config = merged & (2 | 4 | 8 | 64 | 256 | 0x3e00)
			if h.status&(1<<i) != 0 && t.config&6 == 6 {
				if err := h.setIRQ(uint32(t.config>>9&31), true); err != nil {
					return err
				}
				t.asserted = true
			}
			h.arm(i, now)
		case 8:
			if t.config&8 == 0 || t.config&64 != 0 {
				t.match = merged
			}
			if t.config&8 != 0 {
				t.period = t.period&^mask | value&mask
			}
			if t.config&256 != 0 {
				t.match = uint64(uint32(t.match))
				t.period = uint64(uint32(t.period))
			}
			t.config &^= 64
			h.arm(i, now)
		}
	}
	return nil
}
func (h *hpet) mmio(ex hypervisor.X86Exit, cpu hypervisor.X86, now time.Time) error {
	if ex.Size == 0 || ex.Size > 8 || ex.Address&7+uint64(ex.Size) > 8 {
		return fmt.Errorf("unaligned HPET access at %#x size %d", ex.Address, ex.Size)
	}
	if err := h.poll(now); err != nil {
		return err
	}
	offset := ex.Address - hpetAddress
	shift := (offset & 7) * 8
	if !ex.Write {
		cpu.CompleteMMIORead(h.read(offset&^7, now)>>shift, uint32(ex.Size))
		return nil
	}
	var value uint64
	for i := uint8(0); i < ex.Size; i++ {
		value |= uint64(ex.Data[i]) << (8 * i)
	}
	mask := ^uint64(0)
	if ex.Size < 8 {
		mask = (uint64(1) << (8 * ex.Size)) - 1
	}
	return h.write(offset&^7, value<<shift, mask<<shift, now)
}
