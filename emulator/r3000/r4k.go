package r3000

import "math/bits"

const (
	r4kEXL = 1 << 1
	r4kERL = 1 << 2
	r4kKX  = 1 << 7
	r4kFR  = 1 << 26
)

type r4kBus interface {
	read64(address uint64, size uint32) (uint64, bool)
	write64(address uint64, size uint32, data uint64) bool
}

type r4kTLB struct {
	hi, even, odd, mask uint64
}

type r4kCPU struct {
	pc, next, hi, lo uint64
	gpr, cp0, fpr    [32]uint64
	fcsr             uint32
	tlb              [48]r4kTLB
	delaySlot        bool
	reservation      uint64
	linked           bool
}

type r4kInstruction struct {
	code          int
	bad, physical uint64
	target        uint64
	delay, annul  bool
	refill, store bool
	coprocessor   uint64
}

type r4kStep struct {
	pc, address, physical uint64
	word                  uint32
	exception             int
	store                 bool
}

func mipsWord(v uint32) uint64 {
	return uint64(int64(int32(v)))
}

func newR4400() r4kCPU {
	c := r4kCPU{pc: mipsWord(resetPC), next: mipsWord(resetPC + 4)}
	c.cp0[1] = 47
	c.cp0[status] = bev | r4kERL
	c.cp0[15] = 0x0460
	// Big-endian R4400 with an external secondary cache.
	c.cp0[16] = 0x00066643
	for i := range c.tlb {
		c.tlb[i].hi = 0x4000000000 + uint64(i)*8192
	}
	return c
}

func (c *r4kCPU) kernel() bool {
	sr := c.cp0[status]
	return sr&(r4kEXL|r4kERL) != 0 || sr&0x18 == 0
}

const r4kVPN = uint64(0xc00000ffffffe000)

func (c *r4kCPU) probe(hi uint64) int {
	for i, entry := range &c.tlb {
		if (entry.hi^hi)&r4kVPN&^entry.mask == 0 &&
			(entry.even&entry.odd&1 != 0 || (entry.hi^hi)&255 == 0) {
			return i
		}
	}
	return -1
}

func (c *r4kCPU) translate(address uint64, store bool, x *r4kInstruction) uint64 {
	kernel := c.kernel()
	if address == mipsWord(uint32(address)) {
		a := uint32(address)
		switch {
		case a < 0x80000000:
			if c.cp0[status]&r4kERL != 0 {
				return address
			}
		case a < 0xc0000000 && kernel:
			return address & 0x1fffffff
		case !kernel && (a < 0xc0000000 || a >= 0xe0000000 || c.cp0[status]&0x18 != 8):
			x.code = 4
		}
	} else {
		sr := c.cp0[status]
		xbit := uint64(r4kKX)
		if !kernel {
			xbit >>= (sr & 0x18) >> 3
		}
		region := address >> 62
		switch {
		case sr&xbit == 0 || (!kernel && region > uint64(truth(sr&0x18 == 8))):
			x.code = 4
		case region == 2:
			// XKPHYS exposes a 36-bit physical address and a cache attribute.
			if address&0x07fffff000000000 == 0 {
				return address & 0xfffffffff
			}
			x.code = 4
		case address&0x3fffff0000000000 != 0:
			x.code = 4
		}
	}
	if x.code == 4 {
		if store {
			x.code = 5
		}
		x.bad = address
		return 0
	}
	index := c.probe(address&r4kVPN | c.cp0[10]&255)
	if index >= 0 {
		entry := c.tlb[index]
		pageSize := (entry.mask + 0x2000) >> 1
		lo := entry.even
		if address&pageSize != 0 {
			lo = entry.odd
		}
		if lo&2 != 0 {
			if store && lo&4 == 0 {
				x.code, x.bad = 1, address
				return 0
			}
			return (lo&0x3fffffc0)<<6&^(pageSize-1) | address&(pageSize-1)
		}
	}
	x.code, x.bad, x.refill = 2, address, index < 0
	if store {
		x.code = 3
	}
	return 0
}

func (c *r4kCPU) access(bus r4kBus, address uint64, size uint32, write, fetch bool, data uint64, x *r4kInstruction) uint64 {
	if address&uint64(size-1) != 0 {
		x.code, x.bad = 4, address
		if write {
			x.code = 5
		}
		return 0
	}
	physical := c.translate(address, write, x)
	if x.code >= 0 {
		return 0
	}
	x.physical = physical
	if write {
		c.linked = false
		if bus.write64(physical, size, data) {
			return 0
		}
	} else if value, ok := bus.read64(physical, size); ok {
		return value
	}
	x.code, x.bad, x.store = 7, address, write
	if fetch {
		x.code = 6
	}
	return 0
}

func (c *r4kCPU) trap(x r4kInstruction) {
	sr := c.cp0[status]
	why := c.cp0[cause]&0xff00 | uint64(x.code)<<2 | x.coprocessor<<28
	if sr&r4kEXL == 0 {
		c.cp0[epc] = c.pc
		if c.delaySlot {
			why |= 1 << 31
			c.cp0[epc] -= 4
		}
	} else {
		why |= c.cp0[cause] & (1 << 31)
	}
	if x.code >= 1 && x.code <= 5 {
		c.cp0[8] = x.bad
	}
	if x.code >= 1 && x.code <= 3 {
		c.cp0[10] = x.bad&r4kVPN | c.cp0[10]&255
		c.cp0[4] = c.cp0[4]&^0x7ffff0 | (x.bad>>9)&0x7ffff0
		c.cp0[20] = c.cp0[20]&^0x1fffffff0 | (x.bad>>9)&0x7ffffff0 | (x.bad>>31)&0x180000000
	}

	vector := uint32(0x180)
	if x.refill && sr&r4kEXL == 0 {
		vector = 0
		if x.bad != mipsWord(uint32(x.bad)) {
			vector = 0x80
		}
	}
	base := uint32(0x80000000)
	if sr&bev != 0 {
		base = 0xbfc00200
	}
	c.cp0[status], c.cp0[cause] = sr|r4kEXL, why
	c.pc, c.next = mipsWord(base+vector), mipsWord(base+vector+4)
	c.delaySlot, c.linked = false, false
}

func (c *r4kCPU) tick(countTick bool) {
	if countTick {
		count := uint32(c.cp0[9]) + 1
		c.cp0[9] = uint64(count)
		if count == uint32(c.cp0[11]) {
			c.cp0[cause] |= 1 << 15
		}
	}
	if c.cp0[1] <= c.cp0[6] {
		c.cp0[1] = uint64(len(c.tlb) - 1)
	} else {
		c.cp0[1]--
	}
}

func (c *r4kCPU) step(bus r4kBus) r4kStep {
	x := r4kInstruction{code: -1}
	result := r4kStep{pc: c.pc, exception: -1}
	sr := c.cp0[status]
	if sr&7 == 1 && sr&c.cp0[cause]&0xff00 != 0 {
		x.code = 0
	} else {
		result.word = uint32(c.access(bus, c.pc, 4, false, true, 0, &x))
		if x.code < 0 {
			c.execute(bus, result.word, &x)
		}
	}
	if x.code >= 0 {
		c.trap(x)
		result.exception, result.address, result.physical, result.store = x.code, x.bad, x.physical, x.store
	} else if x.annul {
		c.pc, c.next, c.delaySlot = x.target, x.target+4, false
	} else {
		c.pc, c.next, c.delaySlot = c.next, c.next+4, x.delay
		if x.delay {
			c.next = x.target
		}
	}
	c.gpr[0] = 0
	return result
}

func (c *r4kCPU) branch(x *r4kInstruction, taken, likely bool, offset uint64) {
	x.delay, x.annul, x.target = true, likely && !taken, c.pc+8
	if taken {
		x.target = c.pc + 4 + offset
	}
}

func (c *r4kCPU) special(word uint32, a, b uint64, x *r4kInstruction) (uint64, bool) {
	code, shift := word&63, word>>6&31
	switch code {
	case 0:
		return mipsWord(uint32(b) << shift), true
	case 2:
		return mipsWord(uint32(b) >> shift), true
	case 3:
		return uint64(int64(int32(b) >> shift)), true
	case 4:
		return mipsWord(uint32(b) << (a & 31)), true
	case 6:
		return mipsWord(uint32(b) >> (a & 31)), true
	case 7:
		return uint64(int64(int32(b) >> (a & 31))), true
	case 8, 9:
		x.delay, x.target = true, a
		return c.pc + 8, code == 9
	case 12, 13:
		x.code = int(code - 4)
	case 15: // SYNC: bus operations complete in program order.
	case 16:
		return c.hi, true
	case 17:
		c.hi = a
	case 18:
		return c.lo, true
	case 19:
		c.lo = a
	case 20:
		return b << (a & 63), true
	case 22:
		return b >> (a & 63), true
	case 23:
		return uint64(int64(b) >> (a & 63)), true
	case 24, 25:
		product := uint64(uint32(a)) * uint64(uint32(b))
		if code == 24 {
			product = uint64(int64(int32(a)) * int64(int32(b)))
		}
		c.hi, c.lo = mipsWord(uint32(product>>32)), mipsWord(uint32(product))
	case 26, 27:
		if uint32(b) != 0 {
			if code == 26 {
				c.lo, c.hi = mipsWord(uint32(int32(a)/int32(b))), mipsWord(uint32(int32(a)%int32(b)))
			} else {
				c.lo, c.hi = mipsWord(uint32(a)/uint32(b)), mipsWord(uint32(a)%uint32(b))
			}
		}
	case 28, 29:
		c.hi, c.lo = bits.Mul64(a, b)
		if code == 28 {
			if int64(a) < 0 {
				c.hi -= b
			}
			if int64(b) < 0 {
				c.hi -= a
			}
		}
	case 30, 31:
		if b != 0 {
			if code == 30 {
				c.lo, c.hi = uint64(int64(a)/int64(b)), uint64(int64(a)%int64(b))
			} else {
				c.lo, c.hi = a/b, a%b
			}
		}
	case 32, 33, 44, 45:
		return r4kAdd(a, b, code < 40, code&1 == 0, x), true
	case 34, 35, 46, 47:
		difference := a - b
		sign := uint64(1) << 63
		if code < 40 {
			difference, sign = mipsWord(uint32(difference)), 1<<31
		}
		if code&1 == 0 && (a^b)&(a^difference)&sign != 0 {
			x.code = 12
		}
		return difference, true
	case 36:
		return a & b, true
	case 37:
		return a | b, true
	case 38:
		return a ^ b, true
	case 39:
		return ^(a | b), true
	case 42:
		return uint64(truth(int64(a) < int64(b))), true
	case 43:
		return uint64(truth(a < b)), true
	case 48, 49, 50, 51, 52, 54:
		c.compareTrap(code-48, a, b, x)
	case 56, 60:
		return b << (shift + (code-56)*8), true
	case 58, 62:
		return b >> (shift + (code-58)*8), true
	case 59, 63:
		return uint64(int64(b) >> (shift + (code-59)*8)), true
	default:
		x.code = 10
	}
	return 0, false
}

func r4kAdd(a, b uint64, word, trap bool, x *r4kInstruction) uint64 {
	sum := a + b
	sign := uint64(1) << 63
	if word {
		sum, sign = mipsWord(uint32(sum)), 1<<31
	}
	if trap && (a^sum)&(b^sum)&sign != 0 {
		x.code = 12
	}
	return sum
}

func (c *r4kCPU) compareTrap(code uint32, a, b uint64, x *r4kInstruction) {
	condition := false
	switch code {
	case 0:
		condition = int64(a) >= int64(b)
	case 1:
		condition = a >= b
	case 2:
		condition = int64(a) < int64(b)
	case 3:
		condition = a < b
	case 4:
		condition = a == b
	case 6:
		condition = a != b
	}
	if condition {
		x.code = 13
	}
}

func (c *r4kCPU) execute(bus r4kBus, word uint32, x *r4kInstruction) {
	rs, rt, rd := word>>21&31, word>>16&31, word>>11&31
	a, b := c.gpr[rs], c.gpr[rt]
	imm, signed := uint64(word&0xffff), uint64(int64(int16(word)))
	op, dest := word>>26, rt
	var value uint64
	switch op {
	case 0:
		result, write := c.special(word, a, b, x)
		if write && x.code < 0 {
			c.gpr[rd] = result
		}
		return
	case 1:
		switch rt {
		case 0, 1, 2, 3, 16, 17, 18, 19:
			c.branch(x, (int64(a) < 0) == (rt&1 == 0), rt&2 != 0, signed<<2)
			if rt&16 != 0 {
				c.gpr[31] = c.pc + 8
			}
		case 8, 9, 10, 11, 12, 14:
			c.compareTrap(rt-8, a, signed, x)
		default:
			x.code = 10
		}
		return
	case 2, 3:
		x.delay, x.target = true, (c.pc+4)&^0xfffffff|uint64(word&0x3ffffff)<<2
		if op == 3 {
			c.gpr[31] = c.pc + 8
		}
		return
	case 4, 5, 6, 7, 20, 21, 22, 23:
		var taken bool
		switch op & 3 {
		case 0:
			taken = a == b
		case 1:
			taken = a != b
		case 2:
			taken = int64(a) <= 0
		case 3:
			taken = int64(a) > 0
		}
		c.branch(x, taken, op >= 20, signed<<2)
		return
	case 8, 9, 24, 25:
		value = r4kAdd(a, signed, op < 16, op&1 == 0, x)
	case 10:
		value = uint64(truth(int64(a) < int64(signed)))
	case 11:
		value = uint64(truth(a < signed))
	case 12:
		value = a & imm
	case 13:
		value = a | imm
	case 14:
		value = a ^ imm
	case 15:
		value = mipsWord(uint32(imm) << 16)
	case 16:
		c.cop0(word, rs, rt, rd, x)
		return
	case 17:
		c.cop1(word, rs, rt, rd, x)
		return
	case 18, 19:
		x.code, x.coprocessor = 11, uint64(op-16)
		return
	default:
		result, load := c.memory(bus, op, rt, a+signed, x)
		if !load {
			return
		}
		value = result
	}
	if x.code < 0 {
		c.gpr[dest] = value
	}
}
