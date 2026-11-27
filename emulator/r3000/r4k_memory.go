package r3000

func (c *r4kCPU) memory(bus r4kBus, op, rt uint32, address uint64, x *r4kInstruction) (uint64, bool) {
	value := c.gpr[rt]
	switch op {
	case 26, 27, 34, 38:
		size := uint32(4)
		if op < 32 {
			size = 8
		}
		offset := address & uint64(size-1)
		data := c.access(bus, address-offset, size, false, false, 0, x)
		if op == 26 || op == 34 { // LDL or LWL, big endian.
			shift := 8 * offset
			value = data<<shift | value&((uint64(1)<<shift)-1)
		} else {
			shift := 8 * (uint64(size-1) - offset)
			mask := ^uint64(0) >> (64 - 8*size)
			value = data>>shift | value&^(mask>>shift)
		}
		if size == 4 {
			value = mipsWord(uint32(value))
		}
		return value, true
	case 32, 36:
		data := c.access(bus, address, 1, false, false, 0, x)
		if op == 32 {
			data = uint64(int64(int8(data)))
		}
		return data, true
	case 33, 37:
		data := c.access(bus, address, 2, false, false, 0, x)
		if op == 33 {
			data = uint64(int64(int16(data)))
		}
		return data, true
	case 35, 39:
		data := c.access(bus, address, 4, false, false, 0, x)
		if op == 35 {
			data = mipsWord(uint32(data))
		}
		return data, true
	case 40, 41, 43, 63:
		size := uint32(1)
		switch op {
		case 41:
			size = 2
		case 43:
			size = 4
		case 63:
			size = 8
		}
		c.access(bus, address, size, true, false, value, x)
	case 42, 44, 45, 46:
		size := uint64(4)
		if op == 44 || op == 45 {
			size = 8
		}
		offset := address & (size - 1)
		base := address - offset
		first, end, lane := offset, size, uint64(0)
		if op == 45 || op == 46 {
			first, end, lane = 0, offset+1, size-offset-1
		}
		for i := first; i < end && x.code < 0; i++ {
			c.access(bus, base+i, 1, true, false, value>>((size-1-lane)*8), x)
			lane++
		}
	case 47: // CACHE. The instruction and data stores are coherent.
		if !c.kernel() {
			x.code = 10
		} else if rt&0x10 != 0 {
			c.translate(address, false, x)
		}
	case 48, 52:
		size := uint32(4)
		if op == 52 {
			size = 8
		}
		data := c.access(bus, address, size, false, false, 0, x)
		if x.code < 0 {
			c.reservation, c.linked = x.physical, true
			c.cp0[17] = x.physical >> 4
		}
		if size == 4 {
			data = mipsWord(uint32(data))
		}
		return data, true
	case 49, 53, 57, 61:
		if c.cp0[status]&(1<<29) == 0 {
			x.code, x.coprocessor = 11, 1
			break
		}
		switch op {
		case 49:
			data := c.access(bus, address, 4, false, false, 0, x)
			if x.code < 0 {
				c.putFPWord(rt, uint32(data))
			}
		case 53:
			data := c.access(bus, address, 8, false, false, 0, x)
			if x.code < 0 {
				c.fpr[c.fpDoubleReg(rt)] = data
			}
		case 57:
			c.access(bus, address, 4, true, false, uint64(c.fpWord(rt)), x)
		case 61:
			c.access(bus, address, 8, true, false, c.fpr[c.fpDoubleReg(rt)], x)
		}
	case 55:
		return c.access(bus, address, 8, false, false, 0, x), true
	case 56, 60:
		size := uint32(4)
		if op == 60 {
			size = 8
		}
		if address&uint64(size-1) != 0 {
			x.code, x.bad = 5, address
			return 0, false
		}
		physical := c.translate(address, true, x)
		linked := c.linked && c.reservation == physical
		c.linked = false
		if linked && x.code < 0 && !bus.write64(physical, size, value) {
			x.code, x.physical, x.store = 7, physical, true
		}
		return uint64(truth(linked)), true
	default:
		x.code = 10
	}
	return 0, false
}
