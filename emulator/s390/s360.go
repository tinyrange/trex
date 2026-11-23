package s390

import "fmt"

const bytesPer9020SE = 512 << 10

type maintenance9020 struct {
	dar, darMask, checks uint32
	pir                  byte
	atr                  uint64
	atrSet               bool
	psb                  uint32
	local                [4][16]uint32
	delayUntil           uint64
	diagnosticSE1        bool
}

// Restart9020 performs a subsystem PSW restart from the selected storage
// element, leaving the CE and IOCE address translators intact (A27-2734-2
// §11.1.3). The local channel subsystem is reset without clearing storage.
func (m *Machine) Restart9020(storageID int) error {
	c := m.CPUs[0]
	if !m.Model9020 || m.cfg.IOCE || storageID < 1 || storageID > c.storageElements9020() {
		return fmt.Errorf("9020 subsystem restart: invalid CE storage element %d", storageID)
	}
	atr := c.atr9020()
	slot := 0
	for ; slot < 10; slot++ {
		if int(atr>>(36-4*slot)&0xf) == storageID {
			break
		}
	}
	if slot == 10 {
		return fmt.Errorf("9020 subsystem restart: storage element %d is absent from the ATR", storageID)
	}
	physical := uint32(storageID-1) * bytesPer9020SE
	if !m.S.valid(physical, 4096) {
		return fmt.Errorf("9020 subsystem restart: storage element %d has no complete preferential storage area", storageID)
	}
	channelATR := m.CSS.ioceATR
	m.CSS.reset()
	m.CSS.ioceATR = channelATR
	savedATR, atrSet := c.maintenance9020.atr, c.maintenance9020.atrSet
	c.Reset(false)
	c.maintenance9020.atr, c.maintenance9020.atrSet = savedATR, atrSet
	c.maintenance9020.psb, c.Prefix = uint32(slot)*bytesPer9020SE, physical
	if !c.loadPSW(be.Uint64(m.S.Mem[physical:])) {
		return fmt.Errorf("9020 subsystem restart: invalid PSW in storage element %d", storageID)
	}
	c.Stopped = false
	c.Check, c.checkReason = false, ""
	c.next, c.pswChanged = c.PSW.IA, true
	return nil
}

func (c *CPU) storageElements9020() int {
	return min((len(c.S.Mem)+bytesPer9020SE-1)/bytesPer9020SE, 10)
}

func (c *CPU) atr9020() uint64 {
	if c.maintenance9020.atrSet {
		return c.maintenance9020.atr
	}
	var atr uint64
	for i := range c.storageElements9020() {
		atr |= uint64(i+1) << (36 - 4*i)
	}
	return atr
}

func (c *CPU) translate9020(address uint32) uint32 {
	return translateATR9020(c.atr9020(), address)
}

func translateATR9020(atr uint64, address uint32) uint32 {
	slot := address / bytesPer9020SE
	if slot >= 10 {
		return ^uint32(0)
	}
	id := uint32(atr >> (36 - 4*slot) & 0xf)
	if id == 0 {
		return ^uint32(0)
	}
	return (id-1)*bytesPer9020SE | address&(bytesPer9020SE-1)
}

// setATR9020 implements SATR for the CEs available on the system.
func (c *CPU) setATR9020(r1, r2 int) {
	c.privileged()
	selectMask := byte(c.GR[r2])
	if selectMask == 0 {
		c.PSW.CC = 3
		return
	}
	atr := uint64(c.GR[r1])<<8 | uint64(c.GR[r2]>>24)
	for fields := atr; fields != 0; fields >>= 4 {
		if int(fields&0xf) > c.storageElements9020() {
			c.program(pgmSpecification)
		}
	}
	missed := selectMask
	for _, ce := range c.M.CPUs {
		if ce.Addr < 4 && selectMask&(0x80>>ce.Addr) != 0 {
			ce.maintenance9020.atr, ce.maintenance9020.atrSet = atr, true
			ce.purgeTLB()
			ce.ipageValid = false
			missed &^= 0x80 >> ce.Addr
		}
	}
	for _, sub := range c.M.CSS.subs {
		n := sub.devno >> 10
		if n < 3 && missed&(0x04>>n) != 0 {
			c.M.CSS.ioceATR[n] = channelATR9020{Mask: atr, Active: true}
			missed &^= 0x04 >> n
		}
	}
	c.PSW.CC = 0
	if missed != 0 {
		c.GR[r2] = c.GR[r2]&^0xff00 | uint32(missed)<<8
		c.PSW.CC = 1
	}
}

// writeDirect9020 handles the IOCE processor requests of WRD (A27-2734-2
// §8.5.1.7). The CE configuration has channels and no attached processors.
func (c *CPU) writeDirect9020(immediate byte, address uint32) {
	c.privileged()
	function, selected := immediate>>4, immediate&0xf
	if selected == 0 || selected&(selected-1) != 0 || function > 7 {
		c.program(pgmSpecification)
	}
	switch function {
	case 5, 6, 7:
		if selected == 1 {
			c.program(pgmSpecification)
		}
		c.realAbs(address, accFetch)
		c.PSW.CC = 3 // processor did not respond
	default:
		c.program(pgmOperation)
	}
}

// System/360 mode (IBM System/360 Principles of Operation, A22-6821-7).
//
// The CPU runs as in System/370 basic-control mode with these differences:
//   - Only the System/360 operation codes are defined; the System/370
//     additions (MOVE LONG, INSERT CHARACTERS UNDER MASK, the control-register,
//     clock and translation instructions, and others) are operation
//     exceptions.
//   - PSW bit 12 is the USASCII-8 mode bit rather than the EC-mode bit. In
//     USASCII-8 mode decimal results use the preferred signs 1010 (plus) and
//     1011 (minus) and the zone 0101.
//   - There are no control registers: the interval timer and the interrupt
//     key are masked by the PSW's external mask alone.
//   - CCW flag bits 37-39 must be zero (there is no indirect data
//     addressing).

// s360Ops marks the operation codes of System/360 (A22-6821-7, Appendix
// "Instruction Use"): the standard and decimal instruction sets, floating
// point, storage protection and direct control.
var s360Ops = func() (ops [256]bool) {
	for _, op := range []byte{
		0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4e, 0x4f,
		0x50, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
		0x60, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
		0x70, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
		0x80, 0x82, 0x83, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x9c, 0x9d, 0x9e, 0x9f,
		0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xdc, 0xdd, 0xde, 0xdf,
		0xf1, 0xf2, 0xf3, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
	} {
		ops[op] = true
	}
	return
}()

// Preferred decimal sign and zone codes.
const (
	signPlus       = 0xc
	signMinus      = 0xd
	signPlusASCII  = 0xa
	signMinusASCII = 0xb
	zoneEBCDIC     = 0xf
	zoneASCII      = 0x5
)

// decimalSign returns the preferred sign code for a decimal result.
func (c *CPU) decimalSign(neg bool) byte {
	switch {
	case c.PSW.ASCII && neg:
		return signMinusASCII
	case c.PSW.ASCII:
		return signPlusASCII
	case neg:
		return signMinus
	}
	return signPlus
}

// decimalZone returns the preferred zone code for a zoned decimal result.
func (c *CPU) decimalZone() byte {
	if c.PSW.ASCII {
		return zoneASCII
	}
	return zoneEBCDIC
}
