package s390

import "math/bits"

// The 7231 local store has four sectors of sixteen 32-bit words (9020D/E
// System Design Data §5). The maintenance programs link ROS entries by
// placing their addresses and argument blocks after DIAG, as in
// D2101000.SPT and D2740200.SPT in the FAA source archive.
const (
	ioceClearChecks = 0x0f18
	ioceRipple      = 0x0fb8
	ioceScanIn      = 0x1f58
	ioceBeat        = 0x1ea2
	ioceLogSector   = 0x1e20
	ioceFetch       = 0x1e66
)

func (c *CPU) diagnoseIOCE(kernel uint32) {
	switch kernel {
	case ioceClearChecks:
		c.maintenance9020.checks = 0
	case ioceRipple:
		c.ioceRipple()
	default:
		c.program(pgmSpecification)
	}
}

func (c *CPU) ioceRipple() {
	local := &c.maintenance9020.local
	p := c.next
	// Each word in the ripple stream is loaded at the corresponding
	// address in all four sectors, from word 15 down to word zero.
	for word := 15; word >= 0; word-- {
		x := c.fetchWord(p, 0)
		p += 4
		for sector := range local {
			local[sector][word] = x
		}
	}
	if c.fetchHalf(p+2, 0) == ioceScanIn {
		p += 4
		md := c.fetchWord(p, 0)
		lsfr := c.fetchWord(p+16, 0)
		pattern := c.fetchWord(p+28, 0)
		if c.fetchHalf(p+46, 0) != ioceBeat {
			c.program(pgmSpecification)
		}
		// The scan loads the word select from MD and the sector select
		// from LSFR. Beat repeatedly stores L to the selected word.
		// A store of the same value cannot change its result in ideal RAM.
		sector := (lsfr - 2) & 3
		local[sector][md>>12&0xf] = pattern
		p += 48
	}
	kernel := c.fetchHalf(p+2, 0)
	if kernel < ioceLogSector || kernel > ioceLogSector+6 || kernel&1 != 0 {
		c.program(pgmSpecification)
	}
	p += 4
	for _, word := range local[(kernel-ioceLogSector)/2] {
		x := ioceLocalWord(word)
		c.storeWord(p, 0, uint32(x>>4))
		c.storeWord(p+4, 0, uint32(x&0xf)<<4)
		p += 8
	}
	if c.fetchHalf(p+2, 0) != ioceFetch {
		c.program(pgmSpecification)
	}
	c.next = (p + 4) & c.amask
}

// Local store logout emits one odd-parity bit before each group of eight
// data bits. The 36-bit word occupies a doubleword, left justified.
func ioceLocalWord(word uint32) uint64 {
	var result uint64
	for shift := 24; shift >= 0; shift -= 8 {
		x := byte(word >> shift)
		parity := uint64(1 - bits.OnesCount8(x)%2)
		result = result<<9 | parity<<8 | uint64(x)
	}
	return result
}
