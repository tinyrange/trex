// Package r3000 emulates MIPS R3000 Jazz and SGI IP12 workstations.
package r3000

import "fmt"

const (
	resetPC   = 0xbfc00000
	status    = 12
	cause     = 13
	epc       = 14
	bev       = 1 << 22
	isolate   = 1 << 16
	swapCache = 1 << 17
)

type tlbEntry struct{ hi, lo uint32 }
type cacheLine struct {
	tag   uint32
	word  uint32
	valid bool
}

type delayedLoad struct {
	reg   uint8
	value uint32
}

type cpuBus interface {
	readBus(address, size uint32) (uint32, bool)
	writeBus(address, size, value uint32) bool
}

type cpu struct {
	bigEndian        bool
	fpuRevision      uint32
	pc, next, hi, lo uint32
	gpr, cp0, fpr    [32]uint32
	fcsr             uint32
	tlb              [64]tlbEntry
	cache            [2][16384]cacheLine
	delaySlot        bool
	load             delayedLoad
	fpLoad           delayedLoad
	irqDelay         uint8
}

func newCPU() cpu {
	c := cpu{pc: resetPC, next: resetPC + 4, fpLoad: delayedLoad{reg: 32}}
	c.cp0[status], c.cp0[15], c.cp0[1] = bev, 0x200, 63<<8
	for i := range c.tlb {
		c.tlb[i].hi = 0x80000000 | uint32(i)<<12
	}
	return c
}

type instruction struct {
	target          uint32
	branch          bool
	write, load     delayedLoad
	fpWrite, fpLoad delayedLoad
	fpHigh          delayedLoad
	exception       int
	refill          bool
	coprocessor     uint32
	badAddress      uint32
	busAddress      uint32
	busStore        bool
}

func (c *cpu) lookup(address uint32) (tlbEntry, bool) {
	for _, e := range &c.tlb {
		if e.hi>>12 == address>>12 && (e.lo&0x100 != 0 || e.hi&0xfc0 == address&0xfc0) {
			return e, true
		}
	}
	return tlbEntry{}, false
}

func (c *cpu) translate(address uint32, store bool, x *instruction) (uint32, bool) {
	switch {
	case c.cp0[status]&2 != 0 && address >= 0x80000000:
		x.exception = 4
		if store {
			x.exception = 5
		}
	case address >= 0x80000000 && address < 0xc0000000:
		return address & 0x1fffffff, address < 0xa0000000
	default:
		e, found := c.lookup(address&0xfffff000 | c.cp0[10]&0xfc0)
		if found && e.lo&0x200 != 0 {
			if !store || e.lo&0x400 != 0 {
				return e.lo&0xfffff000 | address&0xfff, e.lo&0x800 == 0
			}
			x.exception = 1
		} else {
			x.exception = 2
			if store {
				x.exception = 3
			}
			x.refill = !found && address < 0x80000000
		}
	}
	x.badAddress = address
	return 0, false
}

func (c *cpu) badAddress(address uint32) {
	c.cp0[8] = address
	c.cp0[4] = c.cp0[4]&0xffe00000 | (address>>10)&0x1ffffc
	c.cp0[10] = c.cp0[10]&0xfc0 | address&0xfffff000
}

func (c *cpu) trap(x instruction) {
	c.cp0[cause] = c.cp0[cause]&0xff00 | uint32(x.exception)<<2 | x.coprocessor<<28
	c.cp0[epc] = c.pc
	if c.delaySlot {
		c.cp0[cause] |= 1 << 31
		c.cp0[epc] -= 4
	}
	c.cp0[status] = c.cp0[status]&^0x3f | (c.cp0[status]<<2)&0x3f
	c.pc = 0x80000080
	if c.cp0[status]&bev != 0 {
		c.pc = 0xbfc00180
		if x.refill {
			c.pc = 0xbfc00100
		}
	} else if x.refill {
		c.pc = 0x80000000
	}
	c.next, c.delaySlot, c.irqDelay = c.pc+4, false, 0
}

func (c *cpu) access(bus cpuBus, address, size uint32, store, fetch bool, value uint32, x *instruction) uint32 {
	if address&(size-1) != 0 {
		c.badAddress(address)
		x.badAddress, x.exception = address, 4
		if store {
			x.exception = 5
		}
		return 0
	}
	physical, cached := c.translate(address, store, x)
	if x.exception >= 0 {
		c.badAddress(address)
		return 0
	}
	shift := (physical & 3) * 8
	if c.bigEndian {
		shift = (4 - size - (physical & 3)) * 8
	}
	mask := uint32(0xffffffff) >> (32 - size*8)
	bank := truth(c.cp0[status]&swapCache != 0)
	if !fetch && c.cp0[status]&isolate != 0 {
		index := (physical >> 2) & 16383
		line := &c.cache[bank][index]
		if store {
			if size == 4 {
				*line = cacheLine{physical >> 16, value, true}
			} else if bank == 1 {
				clear(c.cache[bank][index&^3 : index&^3+4])
			} else {
				line.valid = false
			}
		}
		return line.word >> shift & mask
	}
	if cached {
		if fetch {
			bank ^= 1
		}
		index := (physical >> 2) & 16383
		line := &c.cache[bank][index]
		tag := physical >> 16
		if store {
			if bus.writeBus(physical, size, value) {
				if size == 4 {
					*line = cacheLine{tag, value, true}
				} else if line.valid && line.tag == tag {
					line.word = line.word&^(mask<<shift) | (value&mask)<<shift
				}
				return 0
			}
		} else {
			if !line.valid || line.tag != tag {
				words := uint32(1)
				if bank == 1 {
					words = 4
				}
				first := index &^ (words - 1)
				base := physical &^ (words*4 - 1)
				for i := uint32(0); i < words; i++ {
					word, ok := bus.readBus(base+i*4, 4)
					if !ok {
						x.exception, x.busAddress = 7, base+i*4
						if fetch {
							x.exception = 6
						}
						return 0
					}
					c.cache[bank][first+i] = cacheLine{tag, word, true}
				}
			}
			return line.word >> shift & mask
		}
	} else if store {
		if bus.writeBus(physical, size, value) {
			return 0
		}
	} else if word, ok := bus.readBus(physical, size); ok {
		return word
	}
	x.exception, x.busAddress, x.busStore = 7, physical, store
	if fetch {
		x.exception = 6
	}
	return 0
}

func truth(condition bool) uint32 {
	if condition {
		return 1
	}
	return 0
}

func (x *instruction) jump(condition bool, pc, displacement uint32) {
	x.branch, x.target = true, pc+8
	if condition {
		x.target = pc + 4 + displacement
	}
}

func (c *cpu) special(word uint32, rs, rt, rd uint8, x *instruction) {
	a, b := c.gpr[rs], c.gpr[rt]
	shift := (word >> 6) & 31
	var value uint32
	switch word & 63 {
	case 0:
		value = b << shift
	case 2:
		value = b >> shift
	case 3:
		value = uint32(int32(b) >> shift)
	case 4:
		value = b << (a & 31)
	case 6:
		value = b >> (a & 31)
	case 7:
		value = uint32(int32(b) >> (a & 31))
	case 8:
		x.branch, x.target = true, a
		return
	case 9:
		x.branch, x.target, value = true, a, c.pc+8
	case 12:
		x.exception = 8
		return
	case 13:
		x.exception = 9
		return
	case 16:
		value = c.hi
	case 17:
		c.hi = a
		return
	case 18:
		value = c.lo
	case 19:
		c.lo = a
		return
	case 24:
		product := uint64(int64(int32(a)) * int64(int32(b)))
		c.hi, c.lo = uint32(product>>32), uint32(product)
		return
	case 25:
		product := uint64(a) * uint64(b)
		c.hi, c.lo = uint32(product>>32), uint32(product)
		return
	case 26:
		if b != 0 {
			c.lo, c.hi = uint32(int32(a)/int32(b)), uint32(int32(a)%int32(b))
		}
		return
	case 27:
		if b != 0 {
			c.lo, c.hi = a/b, a%b
		}
		return
	case 32, 33:
		value = a + b
		if word&63 == 32 && (a^value)&(b^value)&0x80000000 != 0 {
			x.exception = 12
		}
	case 34, 35:
		value = a - b
		if word&63 == 34 && (a^b)&(a^value)&0x80000000 != 0 {
			x.exception = 12
		}
	case 36:
		value = a & b
	case 37:
		value = a | b
	case 38:
		value = a ^ b
	case 39:
		value = ^(a | b)
	case 42:
		value = truth(int32(a) < int32(b))
	case 43:
		value = truth(a < b)
	default:
		x.exception = 10
	}
	x.write = delayedLoad{rd, value}
}

func (c *cpu) cop0(word uint32, rs, rt, rd uint8, x *instruction) {
	if c.cp0[status]&2 != 0 {
		x.exception = 11
		return
	}
	switch rs {
	case 0:
		x.load = delayedLoad{rt, c.cp0[rd]}
	case 4:
		value := c.gpr[rt]
		switch rd {
		case 1, 15:
		case cause:
			c.cp0[cause] = c.cp0[cause]&^0x300 | value&0x300
		case status:
			old := c.cp0[status]
			c.cp0[status] = value
			if value&1 == 0 {
				c.irqDelay = 0
			} else if old&1 == 0 || value&^old&0xff00 != 0 {
				c.irqDelay = 2
			}
		default:
			c.cp0[rd] = value
		}
	case 8:
		if rt > 1 {
			x.exception = 10
			return
		}
		x.jump(rt == 1, c.pc, uint32(int32(int16(word)))<<2)
	case 16:
		index := c.cp0[0] >> 8 & 63
		switch word & 63 {
		case 1:
			c.cp0[10], c.cp0[2] = c.tlb[index].hi, c.tlb[index].lo
		case 6:
			index = c.cp0[1] >> 8 & 63
			fallthrough
		case 2:
			c.tlb[index] = tlbEntry{c.cp0[10], c.cp0[2]}
		case 8:
			c.cp0[0] |= 1 << 31
			for i, entry := range &c.tlb {
				if entry.hi>>12 == c.cp0[10]>>12 && (entry.lo&0x100 != 0 || entry.hi&0xfc0 == c.cp0[10]&0xfc0) {
					c.cp0[0] = uint32(i) << 8
					break
				}
			}
		case 16:
			c.cp0[status] = c.cp0[status]&^15 | (c.cp0[status]>>2)&15
		default:
			x.exception = 10
		}
	default:
		x.exception = 10
	}
}

func (c *cpu) execute(bus cpuBus, word uint32, x *instruction) {
	rs, rt, rd := uint8(word>>21&31), uint8(word>>16&31), uint8(word>>11&31)
	a, b := c.gpr[rs], c.gpr[rt]
	imm, signed := word&0xffff, uint32(int32(int16(word)))
	address := a + signed
	op := word >> 26
	switch op {
	case 0:
		c.special(word, rs, rt, rd, x)
	case 1:
		if rt != 0 && rt != 1 && rt != 16 && rt != 17 {
			x.exception = 10
			return
		}
		x.jump((int32(a) < 0) == (rt&1 == 0), c.pc, signed<<2)
		if rt&16 != 0 {
			x.write = delayedLoad{31, c.pc + 8}
		}
	case 2, 3:
		x.branch, x.target = true, (c.pc+4)&0xf0000000|(word&0x3ffffff)<<2
		if op == 3 {
			x.write = delayedLoad{31, c.pc + 8}
		}
	case 4:
		x.jump(a == b, c.pc, signed<<2)
	case 5:
		x.jump(a != b, c.pc, signed<<2)
	case 6:
		x.jump(int32(a) <= 0, c.pc, signed<<2)
	case 7:
		x.jump(int32(a) > 0, c.pc, signed<<2)
	case 8, 9:
		if op == 8 && (a^address)&(signed^address)&0x80000000 != 0 {
			x.exception = 12
		}
		x.write = delayedLoad{rt, address}
	case 10:
		x.write = delayedLoad{rt, truth(int32(a) < int32(signed))}
	case 11:
		x.write = delayedLoad{rt, truth(a < signed)}
	case 12:
		x.write = delayedLoad{rt, a & imm}
	case 13:
		x.write = delayedLoad{rt, a | imm}
	case 14:
		x.write = delayedLoad{rt, a ^ imm}
	case 15:
		x.write = delayedLoad{rt, imm << 16}
	case 16:
		c.cop0(word, rs, rt, rd, x)
	case 17:
		c.cop1(word, rs, rt, rd, x)
	case 18, 19:
		x.exception, x.coprocessor = 11, op-16
	case 32, 36:
		data := c.access(bus, address, 1, false, false, 0, x)
		if op == 32 {
			data = uint32(int32(int8(data)))
		}
		x.load = delayedLoad{rt, data}
	case 33, 37:
		data := c.access(bus, address, 2, false, false, 0, x)
		if op == 33 {
			data = uint32(int32(int16(data)))
		}
		x.load = delayedLoad{rt, data}
	case 34, 38:
		data := c.access(bus, address&^3, 4, false, false, 0, x)
		if c.load.reg == rt && rt != 0 {
			b = c.load.value
		}
		offset := address & 3
		if c.bigEndian {
			offset ^= 3
		}
		shift := offset * 8
		if op == 34 {
			data = b&(0x00ffffff>>shift) | data<<(24-shift)
		} else {
			data = b&(0xffffff00<<(24-shift)) | data>>shift
		}
		x.load = delayedLoad{rt, data}
	case 35:
		x.load = delayedLoad{rt, c.access(bus, address, 4, false, false, 0, x)}
	case 40, 41, 43:
		size := uint32(1) << (op - 40)
		if op == 43 {
			size = 4
		}
		c.access(bus, address, size, true, false, b, x)
	case 42, 46:
		offset := address & 3
		if c.bigEndian {
			offset ^= 3
		}
		first, end, shift := uint32(0), offset+1, 3-offset
		if op == 46 {
			first, end, shift = offset, 4, 0
		}
		for i := first; i < end && x.exception < 0; i++ {
			lane := i
			if c.bigEndian {
				lane ^= 3
			}
			c.access(bus, address&^3+lane, 1, true, false, b>>((shift+i-first)*8), x)
		}
	case 49, 57:
		if c.cp0[status]&(1<<29) == 0 {
			x.exception, x.coprocessor = 11, 1
		} else if op == 49 {
			x.fpLoad = delayedLoad{rt, c.access(bus, address, 4, false, false, 0, x)}
		} else {
			c.access(bus, address, 4, true, false, c.fpr[rt], x)
		}
	default:
		x.exception = 10
	}
}

func (c *cpu) step(bus cpuBus) Stop {
	x := instruction{exception: -1, fpWrite: delayedLoad{reg: 32}, fpLoad: delayedLoad{reg: 32}, fpHigh: delayedLoad{reg: 32}}
	result := Stop{PC: c.pc}
	if c.irqDelay == 0 && c.cp0[status]&1 != 0 && c.cp0[status]&c.cp0[cause]&0xff00 != 0 {
		x.exception = 0
	} else {
		if c.irqDelay != 0 {
			c.irqDelay--
		}
		result.Instruction = c.access(bus, c.pc, 4, false, true, 0, &x)
		if x.exception < 0 {
			c.execute(bus, result.Instruction, &x)
		}
	}
	if c.load.reg != 0 {
		c.gpr[c.load.reg] = c.load.value
	}
	if c.fpLoad.reg < 32 {
		c.fpr[c.fpLoad.reg] = c.fpLoad.value
	}
	c.load.reg, c.fpLoad.reg = 0, 32
	if x.exception >= 0 {
		c.trap(x)
		result.Kind, result.Exception = "exception", x.exception
		result.Address, result.Physical, result.Store = x.badAddress, x.busAddress, x.busStore
	} else {
		if x.write.reg != 0 {
			c.gpr[x.write.reg] = x.write.value
		}
		if x.fpWrite.reg < 32 {
			c.fpr[x.fpWrite.reg] = x.fpWrite.value
		}
		if x.fpHigh.reg < 32 {
			c.fpr[x.fpHigh.reg] = x.fpHigh.value
		}
		c.load, c.fpLoad = x.load, x.fpLoad
		c.pc, c.next, c.delaySlot = c.next, c.next+4, x.branch
		if x.branch {
			c.next = x.target
		}
	}
	if c.cp0[1] <= 8<<8 {
		c.cp0[1] = 63 << 8
	} else {
		c.cp0[1] -= 1 << 8
	}
	return result
}

func (c *cpu) readEffective(address uint32, out []byte, read func(uint32, []byte) error) error {
	if uint64(address)+uint64(len(out)) > 1<<32 {
		return fmt.Errorf("r3000: virtual read wraps address space")
	}
	for len(out) > 0 {
		x := instruction{exception: -1}
		p, _ := c.translate(address, false, &x)
		if x.exception >= 0 {
			return fmt.Errorf("r3000: virtual address %#x is not readable", address)
		}
		n := min(len(out), 4096-int(address&4095))
		if err := read(p, out[:n]); err != nil {
			return err
		}
		out = out[n:]
		address += uint32(n)
	}
	return nil
}
