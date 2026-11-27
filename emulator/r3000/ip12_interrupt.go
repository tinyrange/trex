package r3000

// The INT2 interval timers cascade the output of PIT counter 2 (clocked at
// 1 MHz) into counters 0 and 1. Rising outputs remain latched until cleared.
type ip12INT struct {
	reg          [8]byte
	counter      [3]ip12Counter
	microseconds uint64
	pending      byte
}

type ip12Counter struct {
	reload, count uint32
	latch         uint16
	access, mode  byte
	low           byte
	writeHigh     bool
	readHigh      bool
	latched       bool
}

func (c *ip12Counter) write(value byte) {
	count := uint32(value)
	switch c.access {
	case 0:
		return
	case 2:
		count <<= 8
	case 3:
		if !c.writeHigh {
			c.low, c.writeHigh = value, true
			return
		}
		c.writeHigh = false
		count = count<<8 | uint32(c.low)
	}
	if count == 0 {
		count = 65536
	}
	c.reload, c.count = count, count
}

func (c *ip12Counter) read() byte {
	count := uint16(c.count)
	if c.latched {
		count = c.latch
	}
	switch c.access {
	case 2:
		c.latched = false
		return byte(count >> 8)
	case 3:
		if !c.readHigh {
			c.readHigh = true
			return byte(count)
		}
		c.readHigh, c.latched = false, false
		return byte(count >> 8)
	default:
		c.latched = false
		return byte(count)
	}
}

func (c *ip12Counter) advance(ticks uint64) uint64 {
	if c.count == 0 || ticks < uint64(c.count) {
		if c.count != 0 {
			c.count -= uint32(ticks)
		}
		return 0
	}
	ticks -= uint64(c.count)
	if c.mode != 2 && c.mode != 3 {
		c.count = 0
		return 1
	}
	c.count = c.reload - uint32(ticks%uint64(c.reload))
	return 1 + ticks/uint64(c.reload)
}

func (d *ip12INT) update(cycles uint64) {
	d.updatePIT(cycles / 36) // 36 MHz CPU and a 1 MHz PIT input.
}

func (d *ip12INT) updatePIT(now uint64) {
	if now == d.microseconds {
		return
	}
	ticks := d.counter[2].advance(now - d.microseconds)
	d.microseconds = now
	for i := range d.counter[:2] {
		if d.counter[i].advance(ticks) != 0 {
			d.pending |= 1 << i
		}
	}
}

func (d *ip12INT) access(index uint32, value byte, write bool) (uint32, bool) {
	switch index {
	case 0, 2, 4:
		return uint32(d.reg[index]), !write
	case 1, 3, 5, 6, 7:
		if write {
			d.reg[index] = value
		}
		return uint32(d.reg[index]), true
	case 8:
		if write {
			d.pending &^= value & 3
		}
		return 0, write
	case 9:
		return 0, !write
	case 12, 13, 14:
		c := &d.counter[index-12]
		if write {
			c.write(value)
			return 0, true
		}
		return uint32(c.read()), true
	case 15:
		target := value >> 6
		if write && target < 3 {
			c := &d.counter[target]
			access := value >> 4 & 3
			if access == 0 {
				if !c.latched {
					c.latched, c.latch = true, uint16(c.count)
				}
			} else {
				mode := value >> 1 & 7
				if mode >= 6 {
					mode -= 4
				}
				*c = ip12Counter{access: access, mode: mode}
			}
			return 0, true
		}
	}
	return 0, false
}

func (d *ip12INT) interrupts() uint32 {
	return truth(d.reg[0]&d.reg[1] != 0)<<11 | truth(d.reg[2]&d.reg[3] != 0)<<12 |
		uint32(d.pending)<<13
}
