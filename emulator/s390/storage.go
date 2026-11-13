package s390

import "encoding/binary"

var be = binary.BigEndian

// Storage key bits (per 4K absolute frame).
const (
	keyACC   = 0xf0
	keyFetch = 0x08
	keyRef   = 0x04
	keyChg   = 0x02
)

// Storage is absolute main storage shared by every CPU and the channel
// subsystem, with one storage key per 4K frame (ESA/390) or 2K block
// (System/370).
type Storage struct {
	Mem      []byte
	Keys     []byte
	KeyShift uint // log2 of the key-block size
}

func NewStorage(size int) *Storage {
	size = (size + 4095) &^ 4095
	return &Storage{Mem: make([]byte, size), Keys: make([]byte, size>>12), KeyShift: 12}
}

// setKeyBlock sets the key-block size to 1<<shift bytes and clears keys.
func (s *Storage) setKeyBlock(shift uint) {
	s.KeyShift = shift
	s.Keys = make([]byte, len(s.Mem)>>shift)
}

// key returns the storage key of the block holding absolute address a.
func (s *Storage) key(a uint32) *byte { return &s.Keys[a>>s.KeyShift] }

func (s *Storage) Size() uint32 { return uint32(len(s.Mem)) }

// valid reports whether [abs, abs+n) lies within installed storage.
func (s *Storage) valid(abs uint32, n uint32) bool {
	return uint64(abs)+uint64(n) <= uint64(len(s.Mem))
}

// Access kinds.
type access uint8

const (
	accFetch access = iota
	accStore
	accInstr
)

// Program interruption codes.
const (
	pgmOperation          = 0x01
	pgmPrivileged         = 0x02
	pgmExecute            = 0x03
	pgmProtection         = 0x04
	pgmAddressing         = 0x05
	pgmSpecification      = 0x06
	pgmData               = 0x07
	pgmFixedOverflow      = 0x08
	pgmFixedDivide        = 0x09
	pgmDecimalOverflow    = 0x0a
	pgmDecimalDivide      = 0x0b
	pgmHFPOverflow        = 0x0c
	pgmHFPUnderflow       = 0x0d
	pgmHFPSignificance    = 0x0e
	pgmHFPDivide          = 0x0f
	pgmSegment            = 0x10
	pgmPage               = 0x11
	pgmTranslationSpec    = 0x12
	pgmSpecialOperation   = 0x13
	pgmOperand            = 0x15
	pgmTraceTable         = 0x16
	pgmSpaceSwitch        = 0x1c
	pgmHFPSquareRoot      = 0x1d
	pgmPCTranslationSpec  = 0x1f
	pgmAFXTranslation     = 0x20
	pgmASXTranslation     = 0x21
	pgmLXTranslation      = 0x22
	pgmEXTranslation      = 0x23
	pgmPrimaryAuthority   = 0x24
	pgmSecondaryAuthority = 0x25
	pgmALETSpecification  = 0x28
	pgmALENTranslation    = 0x29
	pgmALESequence        = 0x2a
	pgmASTEValidity       = 0x2b
	pgmASTESequence       = 0x2c
	pgmExtendedAuthority  = 0x2d
	pgmStackFull          = 0x30
	pgmStackEmpty         = 0x31
	pgmStackSpecification = 0x32
	pgmStackType          = 0x33
	pgmStackOperation     = 0x34
	pgmMonitor            = 0x40
	pgmPER                = 0x80
)

// programCheck is raised (as a panic value) by instruction execution and
// caught by the CPU's run loop.
type programCheck struct {
	code    uint16
	nullify bool
}

func nullifies(code uint16) bool {
	switch code {
	case pgmSegment, pgmPage, pgmAFXTranslation, pgmASXTranslation, pgmLXTranslation, pgmEXTranslation,
		pgmALENTranslation, pgmALESequence, pgmASTEValidity, pgmASTESequence, pgmExtendedAuthority,
		pgmStackFull, pgmStackEmpty, pgmStackSpecification, pgmStackType, pgmStackOperation,
		pgmPrimaryAuthority, pgmSecondaryAuthority, pgmSpaceSwitch, pgmALETSpecification:
		return true
	}
	return false
}

func (c *CPU) program(code uint16) {
	panic(programCheck{code: code, nullify: nullifies(code)})
}

// tlbEntry caches one virtual page translation for one segment-table designation.
type tlbEntry struct {
	std   uint32
	vpage uint32
	real  uint32 // real frame address
	prot  bool
	valid bool
}

const tlbSize = 1024

// real converts a real address to absolute, applying prefixing.
func (c *CPU) realToAbs(r uint32) uint32 {
	if r < 0x1000 {
		return r + c.Prefix
	}
	if r&^0xfff == c.Prefix {
		return r - c.Prefix
	}
	return r
}

// Address spaces for translation.
const (
	spacePrimary = iota
	spaceSecondary
	spaceAR
	spaceHome
	spaceReal
)

// stdFor returns the segment-table designation used for an operand access
// whose base register is b (for AR mode) in the current translation mode.
func (c *CPU) stdFor(acc access, b int) uint32 {
	mode := c.PSW.AS
	if c.spaceOverride != 0 && acc != accInstr {
		mode = c.spaceOverride & 3
	}
	c.excMode = mode
	switch mode {
	case 0:
		return c.CR[1]
	case 2:
		if acc == accInstr {
			c.excMode = 0
			return c.CR[1]
		}
		return c.CR[7]
	case 3:
		return c.CR[13]
	default: // access-register mode
		if acc == accInstr || b == 0 {
			c.excMode = 0
			return c.CR[1]
		}
		return c.alet(c.AR[b], acc)
	}
}

// translate maps a virtual address to a real address through ESA/390 DAT.
func (c *CPU) translate(v uint32, std uint32, acc access) (real uint32, prot bool) {
	if c.M.S370 {
		return c.translate370(v, acc)
	}
	v &= 0x7fffffff
	vpage := v >> 12
	i := (vpage ^ (std >> 12)) & (tlbSize - 1)
	e := &c.tlb[i]
	if e.valid && e.vpage == vpage && e.std == std {
		return e.real | v&0xfff, e.prot
	}
	if c.CR[0]&0x00f80000 != 0x00b00000 { // bits 8-12 must be 10110
		c.program(pgmTranslationSpec)
	}
	sto := std & 0x7ffff000
	stl := std & 0x7f
	sx := v >> 20 // 11 bits
	if sx>>4 > stl {
		c.excAddr = v
		c.excSpace = std
		c.program(pgmSegment)
	}
	steAddr := (sto + sx*4) & 0x7fffffff
	ste := c.readRealWord(steAddr)
	if ste&0x20 != 0 {
		c.excAddr = v
		c.excSpace = std
		c.program(pgmSegment)
	}
	if ste&0x80000000 != 0 {
		c.program(pgmTranslationSpec)
	}
	pto := ste & 0x7fffffc0
	ptl := ste & 0xf
	px := (v >> 12) & 0xff
	if px>>4 > ptl {
		c.excAddr = v
		c.excSpace = std
		c.program(pgmPage)
	}
	pte := c.readRealWord((pto + px*4) & 0x7fffffff)
	if pte&0x400 != 0 {
		c.excAddr = v
		c.excSpace = std
		c.program(pgmPage)
	}
	if pte&0x80000900 != 0 {
		c.program(pgmTranslationSpec)
	}
	*e = tlbEntry{std: std, vpage: vpage, real: pte & 0x7ffff000, prot: pte&0x200 != 0, valid: true}
	return e.real | v&0xfff, e.prot
}

func (c *CPU) purgeTLB() {
	c.dtlbGen++
	for i := range c.tlb {
		c.tlb[i].valid = false
	}
	c.icache.invalidateAll()
}

// readRealWord fetches a word for DAT tables (real address, no key check).
func (c *CPU) readRealWord(r uint32) uint32 {
	a := c.realAbs(r, accFetch)
	return be.Uint32(c.S.Mem[a:])
}

// realAbs converts a real address of the current program (the guest's when
// interpreting) to a host absolute address, checking it is installed.
func (c *CPU) realAbs(r uint32, acc access) uint32 {
	a := c.realToAbs(r & 0x7fffffff)
	if c.sie != nil {
		a = c.sieHost(a, acc)
	}
	if !c.S.valid(a, 1) {
		c.program(pgmAddressing)
	}
	return a
}

// lowAbs returns the host absolute address of a PSA location.
func (c *CPU) lowAbs(off uint32, acc access) uint32 {
	a := c.Prefix + off
	if c.sie != nil {
		a = c.sieHost(a, acc)
	}
	return a
}

// absolute translates a logical operand address to an absolute address and
// performs protection checks for one access that does not cross a page.
func (c *CPU) absolute(v uint32, acc access, b int) uint32 {
	v &= c.amask
	if v < 4096 || c.sie != nil || c.M.S370 {
		return c.absoluteSlow(v, acc, b)
	}
	std := ^uint32(0) // DAT off
	if c.PSW.DAT {
		// The access register is identified before ART, whose
		// exceptions report it (exception access identification).
		c.excAR = byte(b)
		std = c.stdFor(acc, b)
	}
	vp := v >> 12
	e := &c.dtlb[(vp<<2|uint32(acc))&(dtlbSize-1)]
	if e.vp == vp && e.std == std && e.key == c.PSW.Key && e.acc == acc && e.gen == c.dtlbGen && e.kgen == c.M.keyGen {
		a := e.abs | v&0xfff
		if acc == accStore {
			c.stores++
			if c.M.watchLo <= a && a < c.M.watchHi {
				c.M.watchHit = true
				c.M.watchAddr = a
			}
			c.icache.invalidatePage(a)
		}
		return a
	}
	a := c.absoluteSlow(v, acc, b)
	*e = dtlbEntry{vp: vp, std: std, key: c.PSW.Key, acc: acc, gen: c.dtlbGen, kgen: c.M.keyGen, abs: a &^ 0xfff}
	return a
}

const dtlbSize = 1024

type dtlbEntry struct {
	vp, std, abs uint32
	key          byte
	acc          access
	gen, kgen    uint64
}

// absoluteSlow performs every translation and protection step.
func (c *CPU) absoluteSlow(v uint32, acc access, b int) uint32 {
	var real uint32
	prot := false
	if c.PSW.DAT {
		c.excAR = byte(b)
		std := c.stdFor(acc, b)
		real, prot = c.translate(v, std, acc)
		if acc == accStore && prot {
			c.excAddr = v
			c.excSpace = std
			c.excDATProt = true
			c.program(pgmProtection)
		}
		if acc == accStore && v < 512 && c.CR[0]&0x10000000 != 0 && std&0x100 == 0 {
			c.program(pgmProtection)
		}
	} else {
		real = v
		if acc == accStore && v < 512 && c.CR[0]&0x10000000 != 0 {
			c.program(pgmProtection)
		}
	}
	a := c.realToAbs(real)
	if c.sie != nil {
		a = c.sieHost(a, acc)
	}
	if a >= uint32(len(c.S.Mem)) {
		c.program(pgmAddressing)
	}
	c.checkKey(a, acc, c.PSW.Key, v < 2048)
	return a
}

// checkKey applies key-controlled protection and records reference/change.
// low reports whether the logical address is in 0-2047, the range fetch-
// protection override exempts.
func (c *CPU) checkKey(a uint32, acc access, key byte, low bool) {
	k := c.S.key(a)
	if key != 0 {
		acck := *k >> 4
		if acck != key {
			if acc == accStore {
				if !(acck == 9 && c.CR[0]&0x01000000 != 0) {
					c.program(pgmProtection)
				}
			} else if *k&keyFetch != 0 {
				if !(low && c.CR[0]&0x02000000 != 0) && !(acck == 9 && c.CR[0]&0x01000000 != 0) {
					c.program(pgmProtection)
				}
			}
		}
	}
	if acc == accStore {
		*k |= keyRef | keyChg
		c.stores++
		if c.M.watchLo <= a && a < c.M.watchHi {
			c.M.watchHit = true
			c.M.watchAddr = a
		}
		c.icache.invalidatePage(a)
	} else {
		*k |= keyRef
	}
}

// span returns the absolute slice for n bytes at v. Accesses that cross a
// page boundary return nil; callers then use the byte-wise path.
func (c *CPU) span(v uint32, n uint32, acc access, b int) []byte {
	v &= c.amask
	if v&c.pgMask+n <= c.pgMask+1 {
		a := c.absolute(v, acc, b)
		if acc == accStore && a < c.M.watchHi && a+n > c.M.watchLo {
			c.M.watchHit = true
			c.M.watchAddr = a
		}
		return c.S.Mem[a : a+n]
	}
	return nil
}

func (c *CPU) fetchByte(v uint32, b int) byte {
	a := c.absolute(v, accFetch, b)
	return c.S.Mem[a]
}

func (c *CPU) storeByte(v uint32, b int, x byte) {
	a := c.absolute(v, accStore, b)
	c.S.Mem[a] = x
}

func (c *CPU) fetchHalf(v uint32, b int) uint16 {
	if p := c.span(v, 2, accFetch, b); p != nil {
		return be.Uint16(p)
	}
	return uint16(c.fetchByte(v, b))<<8 | uint16(c.fetchByte(v+1, b))
}

func (c *CPU) fetchWord(v uint32, b int) uint32 {
	if p := c.span(v, 4, accFetch, b); p != nil {
		return be.Uint32(p)
	}
	var x uint32
	for i := uint32(0); i < 4; i++ {
		x = x<<8 | uint32(c.fetchByte(v+i, b))
	}
	return x
}

func (c *CPU) fetchDouble(v uint32, b int) uint64 {
	if p := c.span(v, 8, accFetch, b); p != nil {
		return be.Uint64(p)
	}
	return uint64(c.fetchWord(v, b))<<32 | uint64(c.fetchWord(v+4, b))
}

func (c *CPU) storeHalf(v uint32, b int, x uint16) {
	if p := c.span(v, 2, accStore, b); p != nil {
		be.PutUint16(p, x)
		return
	}
	c.checkStore(v, 2, b)
	c.storeByte(v, b, byte(x>>8))
	c.storeByte(v+1, b, byte(x))
}

func (c *CPU) storeWord(v uint32, b int, x uint32) {
	if p := c.span(v, 4, accStore, b); p != nil {
		be.PutUint32(p, x)
		return
	}
	c.checkStore(v, 4, b)
	for i := uint32(0); i < 4; i++ {
		c.storeByte(v+i, b, byte(x>>(24-8*i)))
	}
}

func (c *CPU) storeDouble(v uint32, b int, x uint64) {
	if p := c.span(v, 8, accStore, b); p != nil {
		be.PutUint64(p, x)
		return
	}
	c.checkStore(v, 8, b)
	c.storeWord(v, b, uint32(x>>32))
	c.storeWord(v+4, b, uint32(x))
}

// checkStore validates that every page of an operand is storable before any
// byte is changed, so a later page fault does not leave a partial update.
func (c *CPU) checkStore(v uint32, n uint32, b int) {
	if n == 0 {
		return
	}
	c.absolute(v, accStore, b)
	last := (v + n - 1) & c.amask
	if last&^c.pgMask != v&c.amask&^c.pgMask {
		c.absolute(last, accStore, b)
	}
}

func (c *CPU) checkFetch(v uint32, n uint32, b int) {
	if n == 0 {
		return
	}
	c.absolute(v, accFetch, b)
	last := (v + n - 1) & c.amask
	if last&^c.pgMask != v&c.amask&^c.pgMask {
		c.absolute(last, accFetch, b)
	}
}

// PSA access helpers used by interruptions.
func (c *CPU) lowWord(off uint32) uint32 {
	return be.Uint32(c.S.Mem[c.lowAbs(off, accFetch):])
}
func (c *CPU) setLowWord(off uint32, x uint32) {
	a := c.lowAbs(off, accStore)
	be.PutUint32(c.S.Mem[a:], x)
	*c.S.key(a) |= keyRef | keyChg
}
func (c *CPU) setLowHalf(off uint32, x uint16) {
	a := c.lowAbs(off, accStore)
	be.PutUint16(c.S.Mem[a:], x)
	*c.S.key(a) |= keyRef | keyChg
}
func (c *CPU) setLowByte(off uint32, x byte) {
	a := c.lowAbs(off, accStore)
	c.S.Mem[a] = x
	*c.S.key(a) |= keyRef | keyChg
}
func (c *CPU) lowDouble(off uint32) uint64 { return be.Uint64(c.S.Mem[c.lowAbs(off, accFetch):]) }
func (c *CPU) setLowDouble(off uint32, x uint64) {
	a := c.lowAbs(off, accStore)
	be.PutUint64(c.S.Mem[a:], x)
	*c.S.key(a) |= keyRef | keyChg
}
