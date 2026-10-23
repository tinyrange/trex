package rfe

import (
	"j5.nz/cc/hypervisor"
	"renvo.dev/rfe/x86"
	"time"
)

// pic implements the AT's pair of fixed-priority 8259s. Edge requests remain
// latched while masked; in-service priority blocks lower-priority requests.
type pic struct {
	base, mask, irr, isr, init, icw1 byte
	readISR, autoEOI, specialMask    bool
}

func first(v byte) int {
	for j := 0; j < 8; j++ {
		if v&(1<<j) != 0 {
			return j
		}
	}
	return 8
}
func (p *pic) pending() int {
	n := first(p.irr &^ p.mask)
	isr := p.isr
	if p.specialMask {
		isr &^= p.mask
	}
	if n >= first(isr) {
		return 8
	}
	return n
}
func (p *pic) accept(n int) {
	p.irr &^= 1 << n
	if !p.autoEOI {
		p.isr |= 1 << n
	}
}
func (p *pic) out(data bool, v byte) {
	if !data {
		if v&16 != 0 {
			p.init = 1
			p.readISR = false
			p.autoEOI = false
			p.specialMask = false
			p.icw1 = v
			p.mask = 0
			p.irr = 0
			p.isr = 0
			return
		}
		if v&8 != 0 {
			if v&0x40 != 0 {
				p.specialMask = v&0x20 != 0
			}
			if v&2 != 0 {
				p.readISR = v&1 != 0
			}
			return
		}
		if v&0x20 != 0 {
			n := first(p.isr)
			if v&0x40 != 0 {
				n = int(v & 7)
			}
			if n < 8 {
				p.isr &^= 1 << n
			}
		}
		return
	}
	switch p.init {
	case 1:
		p.base = v & 0xf8
		p.init = 2
	case 2:
		if p.icw1&1 != 0 {
			p.init = 3
		} else {
			p.init = 0
		}
	case 3:
		p.autoEOI = v&2 != 0
		p.init = 0
	default:
		p.mask = v
	}
}

type timer struct {
	reload                         uint32
	value                          uint16
	access, phase, readPhase, mode byte
	start                          time.Time
	elapsed                        uint64
	latch                          uint16
	latchPhase                     byte
	latched                        bool
}

func (p *timer) count(now time.Time) uint16 {
	if p.start.IsZero() || p.reload == 0 {
		return 0
	}
	ticks := uint64(now.Sub(p.start)) * 1193182 / uint64(time.Second)
	phase := ticks % uint64(p.reload)
	if p.mode == 3 {
		half := uint64((p.reload + 1) / 2)
		if phase >= half {
			phase -= half
		}
		return uint16((p.reload - uint32(phase)*2) & 0xffff)
	}
	return uint16(p.reload - uint32(phase))
}
func (c *cpu) deviceOut(port uint16, v byte) bool {
	ok := c.writeDevice(port, v)
	if ok {
		c.recordPort(port, true, v)
	}
	return ok
}
func (c *cpu) deviceIn(port uint16) (byte, bool) {
	v, ok := c.readDevice(port)
	if ok {
		c.recordPort(port, false, v)
	}
	return v, ok
}
func (c *cpu) recordPort(port uint16, write bool, value byte) {
	c.ioTrace[c.ioSequence%8] = hypervisor.X86Exit{Port: port, Size: 1, Write: write, Data: []byte{value}}
	c.ioSequence++
}
func (c *cpu) writeDevice(port uint16, v byte) bool {
	switch port {
	case 0x20, 0x21, 0xa0, 0xa1:
		j := 0
		if port >= 0xa0 {
			j = 1
		}
		c.pics[j].out(port&1 != 0, v)
		return true
	case 0x43:
		c.pitControls[v]++
		if v>>6 != 0 {
			return true
		} // Channels 1/2 do not raise CPU interrupts.
		p := &c.pit
		if v>>4&3 == 0 {
			if !p.latched {
				p.latch = p.count(time.Now())
				p.latched = true
				p.latchPhase = 0
			}
			return true
		}
		p.latched = false
		p.access = v >> 4 & 3
		p.mode = v >> 1 & 7
		if p.mode >= 6 {
			p.mode -= 4
		}
		p.phase = 0
		p.readPhase = 0
		return true
	case 0x40:
		p := &c.pit
		switch p.access {
		case 1:
			p.value = uint16(v)
		case 2:
			p.value = uint16(v) << 8
		default:
			if p.phase == 0 {
				p.value = uint16(v)
				p.phase = 1
				return true
			}
			p.value |= uint16(v) << 8
			p.phase = 0
		}
		p.reload = uint32(p.value)
		if p.reload == 0 {
			p.reload = 65536
		}
		p.start = time.Now()
		p.elapsed = 0
		return true
	case 0x41, 0x42:
		return true
	}
	return false
}
func (c *cpu) readDevice(port uint16) (byte, bool) {
	switch port {
	case 0x20, 0x21, 0xa0, 0xa1:
		j := 0
		if port >= 0xa0 {
			j = 1
		}
		p := &c.pics[j]
		if port&1 != 0 {
			return p.mask, true
		}
		if p.readISR {
			return p.isr, true
		}
		return p.irr, true
	case 0x40:
		p := &c.pit
		v := p.count(time.Now())
		if p.latched {
			v = p.latch
		}
		if p.access == 2 {
			p.latched = false
			return byte(v >> 8), true
		}
		if p.access == 1 {
			p.latched = false
			return byte(v), true
		}
		if p.latched {
			if p.latchPhase == 0 {
				p.latchPhase = 1
				return byte(v), true
			}
			p.latchPhase = 0
			p.latched = false
			return byte(v >> 8), true
		}
		if p.readPhase == 0 {
			p.readPhase = 1
			return byte(v), true
		}
		p.readPhase = 0
		return byte(v >> 8), true
	case 0x41, 0x42:
		return 0, true
	}
	return 0, false
}
func (c *cpu) interrupts() error {

	edges := c.edges.Swap(0)
	c.pics[0].irr |= byte(edges)
	c.pics[1].irr |= byte(edges >> 8)
	p := &c.pit
	if !p.start.IsZero() && p.reload != 0 {
		ticks := uint64(time.Now().Sub(p.start)) * 1193182 / uint64(time.Second)
		periods := ticks / uint64(p.reload)
		if periods > p.elapsed && (p.mode == 2 || p.mode == 3 || p.elapsed == 0) {
			c.pics[0].irr |= 1
		}
		p.elapsed = periods
	}
	if c.pics[1].pending() < 8 {
		c.pics[0].irr |= 4
	}
	if c.core.Flags&x86.FlagIF == 0 || c.system.IRQShadow != 0 {
		return nil
	}
	n := c.pics[0].pending()
	if n == 8 {
		return nil
	}
	vector := c.pics[0].base + byte(n)
	if n == 2 {
		slave := c.pics[1].pending()
		if slave == 8 {
			return nil
		}
		vector = c.pics[1].base + byte(slave)
		c.pics[1].accept(slave)
	}
	c.pics[0].accept(n)
	return c.system.Interrupt(vector, 0, false)
}
