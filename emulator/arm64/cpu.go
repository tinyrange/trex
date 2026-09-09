// Package arm64 implements bounded AArch64 instruction execution. Firmware,
// devices, memory translation, and execution budgets belong to the caller.
package arm64

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"strconv"
	"strings"

	"github.com/tinyrange/trex/emulator/cpu"
	"golang.org/x/arch/arm64/arm64asm"
)

// CPU owns its architectural register state; Clone does not share mutable state.
type CPU struct {
	DisableDecodeCache bool
	decodeCache        [1024]decodeEntry
	// DisableTranslationCache is useful for differential inspection. Caching is
	// automatically bypassed for observing or device-backed memory adapters.
	DisableTranslationCache bool
	translations            translationCache
	// Scratch is private to a non-reentrant Step call. It holds no architectural
	// state and does not retain caller memory after the instruction completes.
	stepMemory                      translatedMemory
	fetch                           [4]byte
	transfer                        [64]byte
	exclusiveAddress, exclusiveSize uint64
	exclusiveValid                  bool
	x                               [31]uint64
	sp, pc, nzcv                    uint64
	currentEL                       uint64
	daif                            uint64
	cycles                          uint64
	pmcr, pmcnten, divider, pmovs   uint64
	pminten, pmfilter, pmuser       uint64
	ticks, frequency                uint64
	system                          [24]uint64
	q                               [32][16]byte
}

var _ cpu.Processor = (*CPU)(nil)

// New selects a baseline ARMv8-A model without optional crypto, LSE or pointer
// authentication. Identification registers can be configured before execution.
func New() *CPU {
	c := &CPU{}
	c.SetRegister("id_aa64pfr0_el1", 0x11)
	c.SetRegister("id_aa64dfr0_el1", 0x106)
	c.SetRegister("id_aa64mmfr0_el1", 0x0f000005)
	c.SetRegister("midr_el1", 0x000f0000)
	c.SetRegister("ctr_el0", 0x8444c004) // 64-byte minimum I/D cache lines
	c.SetRegister("dczid_el0", 0x10)     // DC ZVA prohibited
	return c
}

func (*CPU) Architecture() cpu.Architecture { return cpu.Architecture{Name: "arm64", PointerSize: 8} }
func (c *CPU) Clone() cpu.Processor {
	v := *c
	v.ClearTranslationCache()
	v.stepMemory = translatedMemory{}
	v.fetch = [4]byte{}
	v.transfer = [64]byte{}
	return &v
}
func (c *CPU) PC() uint64     { return c.pc }
func (c *CPU) SetPC(v uint64) { c.pc = v }

func (c *CPU) Vector(index int) ([16]byte, error) {
	if index < 0 || index >= len(c.q) {
		return [16]byte{}, fmt.Errorf("arm64: vector index out of range")
	}
	return c.q[index], nil
}
func (c *CPU) SetVector(index int, value [16]byte) error {
	if index < 0 || index >= len(c.q) {
		return fmt.Errorf("arm64: vector index out of range")
	}
	c.q[index] = value
	return nil
}
func (c *CPU) Register(name string) (uint64, error) {
	name = strings.ToLower(name)
	if j := systemIndex(name); j >= 0 {
		return c.system[j], nil
	}
	switch name {
	case "daif":
		return c.daif, nil
	case "pmccntr_el0":
		return c.cycles, nil
	case "pmcr_el0":
		return c.pmcr, nil
	case "pmovsclr_el0":
		return c.pmovs, nil
	case "pmintenset_el1", "pmintenclr_el1":
		return c.pminten, nil
	case "pmccfiltr_el0":
		return c.pmfilter, nil
	case "pmuserenr_el0":
		return c.pmuser, nil
	case "cntfrq_el0":
		if c.frequency == 0 {
			return 1000000, nil
		}
		return c.frequency, nil
	case "cntpct_el0", "cntvct_el0":
		return c.ticks, nil
	case "pmcntenset_el0", "pmcntenclr_el0":
		return c.pmcnten, nil
	case "pc":
		return c.pc, nil
	case "sp":
		return c.sp, nil
	case "nzcv":
		return c.nzcv, nil
	case "current_el":
		return c.currentEL, nil
	case "lr":
		return c.x[30], nil
	case "fp":
		return c.x[29], nil
	case "xzr", "wzr":
		return 0, nil
	}
	if len(name) > 1 && (name[0] == 'x' || name[0] == 'w') {
		n, e := strconv.Atoi(name[1:])
		if e == nil && n >= 0 && n < 31 {
			v := c.x[n]
			if name[0] == 'w' {
				v = uint64(uint32(v))
			}
			return v, nil
		}
	}
	return 0, fmt.Errorf("arm64: unknown register %q", name)
}
func (c *CPU) SetRegister(name string, v uint64) error {
	name = strings.ToLower(name)
	if j := systemIndex(name); j >= 0 {
		c.system[j] = v
		if j <= 4 {
			c.ClearTranslationCache()
		}
		return nil
	}
	switch name {
	case "daif":
		c.daif = v & 0x3c0
		return nil
	case "pmccntr_el0":
		c.cycles = v
		return nil
	case "pmcr_el0":
		if v&4 != 0 {
			c.cycles = 0
		}
		c.pmcr = v & 0x79
		return nil
	case "pmovsclr_el0":
		c.pmovs &^= v
		return nil
	case "pmintenset_el1":
		c.pminten |= v & 0x80000000
		return nil
	case "pmintenclr_el1":
		c.pminten &^= v & 0x80000000
		return nil
	case "pmccfiltr_el0":
		c.pmfilter = v
		return nil
	case "pmuserenr_el0":
		c.pmuser = v & 15
		return nil
	case "cntfrq_el0":
		if v == 0 || v > 0xffffffff {
			return fmt.Errorf("arm64: invalid counter frequency")
		}
		c.frequency = v
		return nil
	case "cntpct_el0", "cntvct_el0":
		c.ticks = v
		return nil
	case "pmcntenset_el0":
		c.pmcnten |= v & 0x80000000
		return nil
	case "pmcntenclr_el0":
		c.pmcnten &^= v & 0x80000000
		return nil
	case "pc":
		c.pc = v
		return nil
	case "sp":
		c.sp = v
		return nil
	case "nzcv":
		c.nzcv = v & 0xf0000000
		return nil
	case "current_el":
		if v != 0 && v != 4 && v != 8 && v != 12 {
			return fmt.Errorf("arm64: invalid CurrentEL %#x", v)
		}
		c.currentEL = v
		c.ClearTranslationCache()
		return nil
	case "lr":
		c.x[30] = v
		return nil
	case "fp":
		c.x[29] = v
		return nil
	case "xzr", "wzr":
		return nil
	}
	if len(name) > 1 && (name[0] == 'x' || name[0] == 'w') {
		n, e := strconv.Atoi(name[1:])
		if e == nil && n >= 0 && n < 31 {
			if name[0] == 'w' {
				v = uint64(uint32(v))
			}
			c.x[n] = v
			return nil
		}
	}
	return fmt.Errorf("arm64: unknown register %q", name)
}
func mask(n uint32) uint64 {
	if n == 64 {
		return ^uint64(0)
	}
	return (uint64(1) << n) - 1
}
func sext(v uint64, n uint32) uint64 { return uint64(int64(v<<(64-n)) >> (64 - n)) }
func (c *CPU) r(n uint32, sp bool) uint64 {
	if n == 31 {
		if sp {
			return c.sp
		}
		return 0
	}
	return c.x[n]
}
func (c *CPU) w(n uint32, v uint64, width uint32, sp bool) {
	v &= mask(width)
	if n == 31 {
		if sp {
			c.sp = v
		}
		return
	}
	c.x[n] = v
}
func rotate(v uint64, n, width uint32) uint64 { n %= width; return (v>>n | v<<(width-n)) & mask(width) }
func shift(v uint64, kind, n, width uint32) uint64 {
	v &= mask(width)
	switch kind {
	case 0:
		return v << n & mask(width)
	case 1:
		return v >> n
	case 2:
		return uint64(int64(sext(v, width))>>n) & mask(width)
	default:
		return rotate(v, n, width)
	}
}
func (c *CPU) condition(cond uint32) bool {
	n, z, carry, v := c.nzcv>>31&1 != 0, c.nzcv>>30&1 != 0, c.nzcv>>29&1 != 0, c.nzcv>>28&1 != 0
	var ok bool
	switch cond >> 1 {
	case 0:
		ok = z
	case 1:
		ok = carry
	case 2:
		ok = n
	case 3:
		ok = v
	case 4:
		ok = carry && !z
	case 5:
		ok = n == v
	case 6:
		ok = n == v && !z
	case 7:
		ok = true
	}
	if cond&1 != 0 && cond != 15 {
		ok = !ok
	}
	return ok
}
func (c *CPU) add(a, b, carry uint64, width uint32, flags bool) uint64 {
	a &= mask(width)
	b &= mask(width)
	res, co := bits.Add64(a, b, carry)
	if width == 32 {
		co = res >> 32
	}
	res &= mask(width)
	if flags {
		c.nzcv = 0
		if res>>(width-1) != 0 {
			c.nzcv |= 1 << 31
		}
		if res == 0 {
			c.nzcv |= 1 << 30
		}
		if co != 0 {
			c.nzcv |= 1 << 29
		}
		if (^(a^b)&(a^res))>>(width-1)&1 != 0 {
			c.nzcv |= 1 << 28
		}
	}
	return res
}

// Step leaves the PC at the failing instruction. Unsupported instructions are
// explicit errors, never silently treated as successful firmware operations.
func (c *CPU) Step(m cpu.Memory) (cpu.Effect, error) {
	physical := m
	if c.system[0]&1 != 0 {
		c.stepMemory = translatedMemory{c, m}
		m = &c.stepMemory
		defer func() { c.stepMemory = translatedMemory{} }()
	}
	if c.exclusiveValid {
		m = exclusiveMemory{c, m, physical}
	}
	return c.step(m, physical)
}

// Keep cleanup in the small outer Step so Go can open-code its defer instead
// of routing every decoder return through the runtime defer machinery.
func (c *CPU) step(m, physical cpu.Memory) (cpu.Effect, error) {
	if c.pc&3 != 0 {
		return cpu.Continue, fmt.Errorf("arm64: unaligned PC %#x", c.pc)
	}
	data := &c.fetch
	if err := m.ReadMemory(c.pc, data[:], cpu.Execute); err != nil {
		return cpu.Continue, err
	}
	i := binary.LittleEndian.Uint32(data[:])
	next := c.pc + 4
	effect := cpu.Continue
	rd, rn, rm := i&31, i>>5&31, i>>16&31
	width := uint32(32)
	if i>>31 != 0 {
		width = 64
	}
	unsupported := func() (cpu.Effect, error) {
		inst, _ := arm64asm.Decode(data[:])
		return cpu.Continue, fmt.Errorf("arm64: unsupported instruction at %#x: %08x (%s)", c.pc, i, inst)
	}
	switch c.decode(i) {
	case opPairwise: // ADDP and signed/unsigned MAXP/MINP
		size := 1 << (i >> 22 & 3)
		n := 8
		if i>>30&1 != 0 {
			n = 16
		}
		add := i&0xbf20fc00 == 0x0e20bc00
		if size == 8 && (!add || n == 8) {
			return unsupported()
		}
		var value [16]byte
		for half, reg := range []uint32{rn, rm} {
			for j := 0; j < n/(2*size); j++ {
				var a, b uint64
				for k := 0; k < size; k++ {
					a |= uint64(c.q[reg][j*2*size+k]) << uint(8*k)
					b |= uint64(c.q[reg][j*2*size+size+k]) << uint(8*k)
				}
				v := a + b
				if !add {
					greater := a > b
					if i>>29&1 == 0 {
						greater = int64(sext(a, uint32(size*8))) > int64(sext(b, uint32(size*8)))
					}
					v = b
					if greater != (i>>11&1 != 0) {
						v = a
					}
				}
				for k := 0; k < size; k++ {
					value[half*n/2+j*size+k] = byte(v >> uint(8*k))
				}
			}
		}
		c.q[rd] = value
	case opVectorCompare: // CMGT/CMGE/CMHI/CMHS vector
		size := 1 << (i >> 22 & 3)
		n := 8
		if i>>30&1 != 0 {
			n = 16
		}
		if size == 8 && n == 8 {
			return unsupported()
		}
		var value [16]byte
		for j := 0; j < n; j += size {
			var a, b uint64
			for k := 0; k < size; k++ {
				a |= uint64(c.q[rn][j+k]) << uint(8*k)
				b |= uint64(c.q[rm][j+k]) << uint(8*k)
			}
			greater := a > b
			if i>>29&1 == 0 {
				greater = int64(sext(a, uint32(8*size))) > int64(sext(b, uint32(8*size)))
			}
			if greater || i>>11&1 != 0 && a == b {
				for k := 0; k < size; k++ {
					value[j+k] = 255
				}
			}
		}
		c.q[rd] = value
	case opVectorCompareZero: // CMLT vector elements, zero
		size := 1 << (i >> 22 & 3)
		n := 8
		if i>>30&1 != 0 {
			n = 16
		}
		if size == 8 && n == 8 {
			return unsupported()
		}
		var value [16]byte
		for j := 0; j < n; j += size {
			if c.q[rn][j+size-1]&0x80 != 0 {
				for k := 0; k < size; k++ {
					value[j+k] = 255
				}
			}
		}
		c.q[rd] = value
	case opDataCache: // DC CVAC/CVAU/CIVAC/IVAC
		// The interpreter has coherent instruction/data memory and no cache.
		// Validate the address translation even though no cache line is retained.
		if _, err := c.Translate(physical, c.r(rd, false), cpu.Read); err != nil {
			return effect, err
		}
	case opICacheAll: // IC IALLU/IALLUIS
		if c.currentEL == 0 {
			return effect, fmt.Errorf("arm64: instruction cache invalidation at EL0")
		}
	case opICacheAddress: // IC IVAU
		if _, err := c.Translate(physical, c.r(rd, false), cpu.Read); err != nil {
			return effect, err
		}
	case opVectorExtract: // UMOV/SMOV vector lane to GPR
		imm := i >> 16 & 31
		if imm == 0 {
			return unsupported()
		}
		log := uint32(bits.TrailingZeros32(imm))
		size := uint32(1) << log
		wide, signed := i>>30&1 != 0, i>>12&1 == 0
		if log > 3 || !signed && (wide != (size == 8)) || signed && (size == 8 || size == 4 && !wide) {
			return unsupported()
		}
		index := imm >> (log + 1)
		var v uint64
		for j := uint32(0); j < size; j++ {
			v |= uint64(c.q[rn][index*size+j]) << (8 * j)
		}
		if signed {
			v = sext(v, size*8)
		}
		w := uint32(32)
		if wide {
			w = 64
		}
		c.w(rd, v, w, false)
	case opAddWide: // SADDW/UADDW/SSUBW/USUBW
		size := 1 << (i >> 22 & 3)
		if size == 8 {
			return unsupported()
		}
		base := 0
		if i>>30&1 != 0 {
			base = 8
		}
		var value [16]byte
		for j := 0; j < 8/size; j++ {
			var a, b uint64
			for k := 0; k < 2*size; k++ {
				a |= uint64(c.q[rn][j*2*size+k]) << uint(8*k)
			}
			for k := 0; k < size; k++ {
				b |= uint64(c.q[rm][base+j*size+k]) << uint(8*k)
			}
			if i>>29&1 == 0 {
				b = sext(b, uint32(size*8))
			}
			if i>>13&1 != 0 {
				a -= b
			} else {
				a += b
			}
			for k := 0; k < 2*size; k++ {
				value[j*2*size+k] = byte(a >> uint(8*k))
			}
		}
		c.q[rd] = value
	case opVectorSum: // ADDV
		size := 1 << (i >> 22 & 3)
		n := 8
		if i>>30&1 != 0 {
			n = 16
		}
		if size == 8 || size == 4 && n == 8 {
			return unsupported()
		}
		var sum uint64
		for j := 0; j < n; j += size {
			for k := 0; k < size; k++ {
				sum += uint64(c.q[rn][j+k]) << uint(8*k)
			}
		}
		c.q[rd] = [16]byte{}
		for k := 0; k < size; k++ {
			c.q[rd][k] = byte(sum >> uint(8*k))
		}
	case opShiftLong: // SSHLL/USHLL, including SXTL/UXTL aliases
		imm := i >> 16 & 127
		if imm < 8 || imm >= 64 {
			return unsupported()
		}
		bitsPerLane := uint32(1) << uint(bits.Len32(imm)-1)
		size, amount := int(bitsPerLane/8), imm-bitsPerLane
		base := 0
		if i>>30&1 != 0 {
			base = 8
		}
		var value [16]byte
		for j := 0; j < 8/size; j++ {
			var lane uint64
			for k := 0; k < size; k++ {
				lane |= uint64(c.q[rn][base+j*size+k]) << uint(8*k)
			}
			if i>>29&1 == 0 {
				lane = sext(lane, bitsPerLane)
			}
			lane <<= amount
			for k := 0; k < 2*size; k++ {
				value[j*2*size+k] = byte(lane >> uint(8*k))
			}
		}
		c.q[rd] = value
	case opAcquireRelease: // LDAR/STLR, including byte and halfword forms
		size := 1 << (i >> 30)
		address := c.r(rn, true)
		if address&uint64(size-1) != 0 {
			return effect, fmt.Errorf("arm64: unaligned acquire/release access %#x", address)
		}
		data := c.transfer[:8]
		if i>>22&1 != 0 {
			if err := m.ReadMemory(address, data[:size], cpu.Read); err != nil {
				return effect, err
			}
			c.loadReg(data[:size], rd, false, false)
		} else {
			c.storeReg(data[:size], rd, false)
			if err := m.WriteMemory(address, data[:size]); err != nil {
				return effect, err
			}
		}
	case opVectorSingleStructure: // LD/ST single SIMD structure elements
		if i>>23&1 == 0 && rm != 0 {
			return unsupported()
		}
		q, s, sz := i>>30&1, i>>12&1, i>>10&3
		opcode := i >> 13 & 7
		count := int((opcode&1)<<1|(i>>21&1)) + 1
		scale := opcode >> 1
		index := uint32(0)
		load, replicate := i>>22&1 != 0, scale == 3
		switch scale {
		case 0:
			index = q<<3 | s<<2 | sz
		case 1:
			if sz&1 != 0 {
				return unsupported()
			}
			index = q<<2 | s<<1 | sz>>1
		case 2:
			if sz&2 != 0 {
				return unsupported()
			}
			index = q<<1 | s
			if sz&1 != 0 {
				if s != 0 {
					return unsupported()
				}
				scale, index = 3, q
			}
		case 3:
			if !load || s != 0 {
				return unsupported()
			}
			scale = sz
		}
		size := 1 << scale
		address := c.r(rn, true)
		data := c.transfer[:32]
		if load {
			if err := m.ReadMemory(address, data[:count*size], cpu.Read); err != nil {
				return effect, err
			}
			for j := 0; j < count; j++ {
				reg := (rd + uint32(j)) & 31
				if replicate {
					c.q[reg] = [16]byte{}
					for k := 0; k < 8<<q; k += size {
						copy(c.q[reg][k:k+size], data[j*size:(j+1)*size])
					}
				} else {
					copy(c.q[reg][int(index)*size:int(index+1)*size], data[j*size:(j+1)*size])
				}
			}
		} else {
			for j := 0; j < count; j++ {
				copy(data[j*size:(j+1)*size], c.q[(rd+uint32(j))&31][int(index)*size:int(index+1)*size])
			}
			if err := m.WriteMemory(address, data[:count*size]); err != nil {
				return effect, err
			}
		}
		if i>>23&1 != 0 {
			delta := uint64(count * size)
			if rm != 31 {
				delta = c.r(rm, false)
			}
			c.w(rn, address+delta, 64, true)
		}
	case opVectorAddSub: // ADD/SUB vector elements
		size := 1 << uint(i>>22&3)
		n := 8
		if i>>30&1 != 0 {
			n = 16
		}
		if size == 8 && n == 8 {
			return unsupported()
		}
		var value [16]byte
		for j := 0; j < n; j += size {
			var a, b uint64
			for k := 0; k < size; k++ {
				a |= uint64(c.q[rn][j+k]) << uint(8*k)
				b |= uint64(c.q[rm][j+k]) << uint(8*k)
			}
			sum := a + b
			if i>>29&1 != 0 {
				sum = a - b
			}
			for k := 0; k < size; k++ {
				value[j+k] = byte(sum >> uint(8*k))
			}
		}
		c.q[rd] = value
	case opVectorInsert: // INS vector element from general register (MOV alias)
		imm := i >> 16 & 31
		if imm == 0 {
			return unsupported()
		}
		log := uint32(bits.TrailingZeros32(imm))
		if log > 3 {
			return unsupported()
		}
		size := uint32(1) << log
		index := imm >> (log + 1)
		value := c.r(rn, false)
		for j := uint32(0); j < size; j++ {
			c.q[rd][index*size+j] = byte(value >> (8 * j))
		}
	case opCSDB: // No speculative execution exists in this interpreter.
	case opReverseBits: // RBIT
		v := bits.Reverse64(c.r(rn, false) & mask(width))
		if width == 32 {
			v >>= 32
		}
		c.w(rd, v, width, false)
	case opAddLong: // SADDLV/UADDLV
		size := 1 << uint(i>>22&3)
		n := 8
		if i>>30&1 != 0 {
			n = 16
		}
		if size == 8 || size == 4 && n == 8 {
			return unsupported()
		}
		sum := uint64(0)
		for j := 0; j < n; j += size {
			var lane uint64
			for k := 0; k < size; k++ {
				lane |= uint64(c.q[rn][j+k]) << uint(8*k)
			}
			if i>>29&1 == 0 {
				lane = sext(lane, uint32(size*8))
			}
			sum += lane
		}
		c.q[rd] = [16]byte{}
		for j := 0; j < 2*size; j++ {
			c.q[rd][j] = byte(sum >> uint(8*j))
		}
	case opShiftNarrow: // SHRN/SHRN2
		imm := i >> 16 & 127
		h := imm >> 3
		if h == 0 || h >= 8 {
			return unsupported()
		}
		elementBits := uint32(8) << uint(bits.Len32(h)-1)
		amount := 2*elementBits - imm
		size := int(elementBits / 8)
		source := c.q[rn]
		value := [16]byte{}
		base := 0
		if i>>30&1 != 0 {
			value = c.q[rd]
			base = 8
		}
		for j := 0; j < 8/size; j++ {
			var lane uint64
			for k := 0; k < 2*size; k++ {
				lane |= uint64(source[j*2*size+k]) << uint(k*8)
			}
			lane >>= amount
			for k := 0; k < size; k++ {
				value[base+j*size+k] = byte(lane >> uint(k*8))
			}
		}
		c.q[rd] = value
	case opVectorEqual: // CMEQ vector elements or zero
		size := 1 << uint(i>>22&3)
		n := 8
		if i>>30&1 != 0 {
			n = 16
		}
		if size == 8 && n == 8 {
			return unsupported()
		}
		var value [16]byte
		for j := 0; j < n; j += size {
			equal := true
			for k := 0; k < size; k++ {
				right := byte(0)
				if i&0xbf20fc00 == 0x2e208c00 {
					right = c.q[rm][j+k]
				}
				equal = equal && c.q[rn][j+k] == right
			}
			if equal {
				for k := 0; k < size; k++ {
					value[j+k] = 255
				}
			}
		}
		c.q[rd] = value
	case opClearExclusive: // CLREX
		c.exclusiveValid = false
	case opExclusive: // single-register exclusive load/store
		size := 1 << uint(i>>30)
		address := c.r(rn, true)
		if address&uint64(size-1) != 0 {
			return effect, fmt.Errorf("arm64: unaligned exclusive access %#x", address)
		}
		pa, err := c.Translate(physical, address, cpu.Read)
		if err != nil {
			return effect, err
		}
		data := c.transfer[:8]
		if i>>22&1 != 0 {
			if i>>16&31 != 31 {
				return unsupported()
			}
			if err := m.ReadMemory(address, data[:size], cpu.Read); err != nil {
				return effect, err
			}
			c.loadReg(data[:size], rd, false, false)
			c.exclusiveAddress = pa
			c.exclusiveSize = uint64(size)
			c.exclusiveValid = true
		} else {
			status := uint64(1)
			if c.exclusiveValid && c.exclusiveAddress == pa && c.exclusiveSize == uint64(size) {
				c.storeReg(data[:size], rd, false)
				if err := m.WriteMemory(address, data[:size]); err != nil {
					return effect, err
				}
				status = 0
			}
			c.exclusiveValid = false
			c.w(i>>16&31, status, 32, false)
		}
	case opMultiplyLong: // SMADDL/UMADDL/SMSUBL/UMSUBL (and MUL aliases)
		a, b := uint64(uint32(c.r(rn, false))), uint64(uint32(c.r(rm, false)))
		if i>>23&1 == 0 {
			a = sext(a, 32)
			b = sext(b, 32)
		}
		v := a * b
		acc := c.r(i>>10&31, false)
		if i>>15&1 != 0 {
			v = acc - v
		} else {
			v += acc
		}
		c.w(rd, v, 64, false)
	case opMultiplyHigh: // SMULH/UMULH
		a, b := c.r(rn, false), c.r(rm, false)
		hi, _ := bits.Mul64(a, b)
		if i>>23&1 == 0 {
			if int64(a) < 0 {
				hi -= b
			}
			if int64(b) < 0 {
				hi -= a
			}
		}
		c.w(rd, hi, 64, false)
	case opPointerAuthHint: // PACIBSP/AUTIBSP are HINTs without FEAT_PAuth.
	case opVectorToGeneral: // FMOV general register from SIMD scalar
		c.w(rd, binary.LittleEndian.Uint64(c.q[rn][:8]), width, false)
	case opGeneralToVector: // FMOV SIMD scalar from general register
		c.q[rd] = [16]byte{}
		binary.LittleEndian.PutUint64(c.q[rd][:8], c.r(rn, false)&mask(width))
	case opVectorStructures: // SIMD multiple structures
		count := 0
		interleave := false
		switch i >> 12 & 15 {
		case 8:
			count = 2
			interleave = true
		case 4:
			count = 3
			interleave = true
		case 0:
			count = 4
			interleave = true
		case 7:
			count = 1
		case 10:
			count = 2
		case 6:
			count = 3
		case 2:
			count = 4
		default:
			return unsupported()
		}
		size := 8
		if i>>30&1 != 0 {
			size = 16
		}
		element := 1 << (i >> 10 & 3)
		if interleave && size == 8 && element == 8 {
			return unsupported()
		}
		at := func(reg, laneByte int) int {
			if interleave {
				return ((laneByte/element)*count+reg)*element + laneByte%element
			}
			return reg*size + laneByte
		}
		address := c.r(rn, true)
		data := c.transfer[:64]
		load := i>>22&1 != 0
		if load {
			if err := m.ReadMemory(address, data[:count*size], cpu.Read); err != nil {
				return effect, err
			}
			for j := 0; j < count; j++ {
				reg := (rd + uint32(j)) & 31
				c.q[reg] = [16]byte{}
				for k := 0; k < size; k++ {
					c.q[reg][k] = data[at(j, k)]
				}
			}
		} else {
			for j := 0; j < count; j++ {
				for k := 0; k < size; k++ {
					data[at(j, k)] = c.q[(rd+uint32(j))&31][k]
				}
			}
			if err := m.WriteMemory(address, data[:count*size]); err != nil {
				return effect, err
			}
		}
		if i>>23&1 != 0 {
			offset := c.r(rm, false)
			if rm == 31 {
				offset = uint64(count * size)
			}
			c.w(rn, address+offset, 64, true)
		}
	case opVectorLogical: // vector logical operations and bit selection
		n := 8
		if i>>30&1 != 0 {
			n = 16
		}
		var value [16]byte
		for j := 0; j < n; j++ {
			a, b, d := c.q[rn][j], c.q[rm][j], c.q[rd][j]
			switch (i>>29&1)<<2 | (i >> 22 & 3) {
			case 0:
				value[j] = a & b
			case 1:
				value[j] = a &^ b
			case 2:
				value[j] = a | b
			case 3:
				value[j] = a | ^b
			case 4:
				value[j] = a ^ b
			case 5:
				value[j] = a&d | b&^d // BSL
			case 6:
				value[j] = a&b | d&^b // BIT
			case 7:
				value[j] = a&^b | d&b // BIF
			}
		}
		c.q[rd] = value
	case opVectorDuplicate: // DUP vector elements from a general register
		element := i >> 16 & 31
		if element != 1 && element != 2 && element != 4 && element != 8 {
			return unsupported()
		}
		n := 8
		if i>>30&1 != 0 {
			n = 16
		}
		if element == 8 && n == 8 {
			return unsupported()
		}
		v := c.r(rn, false)
		c.q[rd] = [16]byte{}
		for j := 0; j < n; j++ {
			c.q[rd][j] = byte(v >> (8 * (uint32(j) % element)))
		}
	case opTLBI: // EL1 TLBI
		c.ClearTranslationCache()
		if c.currentEL == 0 {
			return effect, fmt.Errorf("arm64: TLBI at EL0")
		}
	case opBarrier:
		// ISB/DMB/DSB: this single-CPU interpreter completes memory operations
		// synchronously and has no instruction cache or outstanding accesses.
	case opAddressTranslate: // AT S1E1R/W
		access := cpu.Read
		if i>>5&1 != 0 {
			access = cpu.Write
		}
		pa, attributes, err := c.translate(physical, c.r(rd, false), access)
		if fault, ok := err.(*TranslationFault); ok {
			c.system[10] = 1 | fault.Status<<1
		} else if err != nil {
			return effect, err
		} else {
			c.system[10] = pa&0x0000fffffffff000 | attributes
		}
	case opDAIFImmediate: // MSR DAIFSet/DAIFClr,#imm4
		if c.currentEL == 0 {
			return effect, fmt.Errorf("arm64: DAIF immediate access at EL0")
		}
		v := uint64(i>>8&15) << 6
		if i>>5&1 == 0 {
			c.daif |= v
		} else {
			c.daif &^= v
		}
	case opSystem: // MRS/MSR system register
		if i&0xffffffe0 == 0xd5384240 {
			c.w(rd, c.currentEL, 64, false)
			break
		}
		ok, err := c.systemInstruction(i)
		if err != nil {
			return effect, err
		}
		if !ok {
			return unsupported()
		}
	case opCurrentEL: // MRS CurrentEL
		c.w(rd, c.currentEL, 64, false)
	case opVectorImmediate: // MOVI/MVNI and vector ORR/BIC immediate
		v := uint64((i>>16&7)<<5 | i>>5&31)
		mode, op := i>>12&15, i>>29&1
		size := 4
		merge := mode < 12 && mode&1 != 0
		switch {
		case mode < 8:
			v <<= (mode >> 1) * 8
		case mode < 12:
			size = 2
			v <<= ((mode >> 1) & 1) * 8
		case mode < 14:
			shift := uint32(8) * (mode - 11)
			v = v<<shift | mask(shift)
		case mode == 14:
			size = 1
			if op != 0 {
				size = 8
				immediate := v
				v = 0
				for j := uint32(0); j < 8; j++ {
					if immediate>>j&1 != 0 {
						v |= uint64(255) << (j * 8)
					}
				}
			}
		default:
			return unsupported()
		}
		if op != 0 && mode != 14 {
			v = ^v
		}
		previous := c.q[rd]
		c.q[rd] = [16]byte{}
		n := 8
		if i>>30&1 != 0 {
			n = 16
		}
		for j := 0; j < n; j++ {
			b := byte(v >> uint(8*(j%size)))
			if merge {
				if op != 0 {
					b &= previous[j]
				} else {
					b |= previous[j]
				}
			}
			c.q[rd][j] = b
		}
	case opNop: // NOP
	case opReturn:
		next = c.r(rn, false)
		effect = cpu.Return
	case opBranchReg:
		next = c.r(rn, false)
	case opBranchLinkReg:
		next = c.r(rn, false)
		c.x[30] = c.pc + 4
		effect = cpu.Call
	case opBranchImmediate:
		next = c.pc + (sext(uint64(i&0x3ffffff), 26) << 2)
		if i>>31 != 0 {
			c.x[30] = c.pc + 4
			effect = cpu.Call
		}
	case opBranchConditional:
		if c.condition(i & 15) {
			next = c.pc + (sext(uint64(i>>5&0x7ffff), 19) << 2)
		}
	case opCompareBranch:
		if (c.r(rd, false)&mask(width) == 0) == (i>>24&1 == 0) {
			next = c.pc + (sext(uint64(i>>5&0x7ffff), 19) << 2)
		}
	case opTestBranch:
		bit := (i>>31)<<5 | i>>19&31
		if (c.r(rd, false)>>bit&1 == 0) == (i>>24&1 == 0) {
			next = c.pc + (sext(uint64(i>>5&0x3fff), 14) << 2)
		}
	case opAddress:
		imm := sext(uint64(i>>5&0x7ffff)<<2|uint64(i>>29&3), 21)
		base := c.pc
		if i>>31 != 0 {
			base &^= 4095
			imm <<= 12
		}
		c.w(rd, base+imm, 64, false)
	case opMoveWide: // MOVN/MOVZ/MOVK
		s := i >> 21 & 3
		if width == 32 && s > 1 {
			return unsupported()
		}
		v := uint64(i>>5&0xffff) << (s * 16)
		switch i >> 29 & 3 {
		case 0:
			v = ^v
		case 2:
		case 3:
			v = c.r(rd, false)&^(uint64(0xffff)<<(s*16)) | v
		default:
			return unsupported()
		}
		c.w(rd, v, width, false)
	case opAddSub:
		immediate := i&0x1f000000 == 0x11000000
		extended := !immediate && i>>21&1 != 0
		flags := i>>29&1 != 0
		a := c.r(rn, immediate || extended)
		var b uint64
		if immediate {
			b = uint64(i >> 10 & 0xfff)
			if i>>22&1 != 0 {
				b <<= 12
			}
		} else if extended {
			opt := i >> 13 & 7
			n := uint32(8) << (opt & 3)
			b = c.r(rm, false) & mask(n)
			if opt&4 != 0 {
				b = sext(b, n)
			}
			s := i >> 10 & 7
			if s > 4 {
				return unsupported()
			}
			b <<= s
		} else {
			s := i >> 10 & 63
			kind := i >> 22 & 3
			if s >= width || kind == 3 {
				return unsupported()
			}
			b = shift(c.r(rm, false), kind, s, width)
		}
		carry := uint64(0)
		if i>>30&1 != 0 {
			b = ^b
			carry = 1
		}
		c.w(rd, c.add(a, b, carry, width, flags), width, !flags && (immediate || extended))
	case opAddCarry:
		b := c.r(rm, false)
		if i>>30&1 != 0 {
			b = ^b
		}
		c.w(rd, c.add(c.r(rn, false), b, c.nzcv>>29&1, width, i>>29&1 != 0), width, false)
	case opLogical:
		var b uint64
		if i&0x1f800000 == 0x12000000 {
			var ok bool
			b, _, ok = bitMasks(i>>22&1, i>>10&63, i>>16&63, width, true)
			if !ok {
				return unsupported()
			}
		} else {
			s := i >> 10 & 63
			if s >= width {
				return unsupported()
			}
			b = shift(c.r(rm, false), i>>22&3, s, width)
			if i>>21&1 != 0 {
				b = ^b
			}
		}
		a := c.r(rn, false)
		var v uint64
		switch i >> 29 & 3 {
		case 0, 3:
			v = a & b
		case 1:
			v = a | b
		case 2:
			v = a ^ b
		}
		v &= mask(width)
		if i>>29&3 == 3 {
			c.nzcv = 0
			if v == 0 {
				c.nzcv |= 1 << 30
			}
			if v>>(width-1) != 0 {
				c.nzcv |= 1 << 31
			}
		}
		c.w(rd, v, width, i&0x1f800000 == 0x12000000 && i>>29&3 != 3)
	case opBitfield: // SBFM/BFM/UBFM
		wm, tm, ok := bitMasks(i>>22&1, i>>10&63, i>>16&63, width, false)
		if !ok {
			return unsupported()
		}
		src := c.r(rn, false) & mask(width)
		v := rotate(src, i>>16&63, width) & wm
		switch i >> 29 & 3 {
		case 0:
			top := uint64(0)
			if src>>(i>>10&63)&1 != 0 {
				top = ^uint64(0)
			}
			v = v&tm | top&^tm
		case 1:
			v = c.r(rd, false)&^wm | v
			v = c.r(rd, false)&^tm | v&tm
		case 2:
			v &= tm
		default:
			return unsupported()
		}
		c.w(rd, v, width, false)
	case opExtract:
		s := i >> 10 & 63
		if s >= width {
			return unsupported()
		}
		v := (c.r(rm, false) & mask(width)) >> s
		if s != 0 {
			v |= (c.r(rn, false) & mask(width)) << (width - s)
		}
		c.w(rd, v, width, false)
	case opConditionalCompare: // conditional compare, register or immediate
		if c.condition(i >> 12 & 15) {
			b := c.r(rm, false)
			if i>>11&1 != 0 {
				b = uint64(rm)
			}
			carry := uint64(0)
			if i>>30&1 != 0 {
				b = ^b
				carry = 1
			}
			c.add(c.r(rn, false), b, carry, width, true)
		} else {
			c.nzcv = uint64(i&15) << 28
		}
	case opConditionalSelect: // conditional select
		v := c.r(rn, false)
		if !c.condition(i >> 12 & 15) {
			v = c.r(rm, false)
			if i>>30&1 != 0 {
				v = ^v
			}
			if i>>10&1 != 0 {
				v++
			}
		}
		c.w(rd, v, width, false)
	case opCountLeadingZeros: // CLZ
		v := c.r(rn, false) & mask(width)
		c.w(rd, uint64(bits.LeadingZeros64(v))-uint64(64-width), width, false)
	case opReverseBytes: // REV16/REV32/REV64
		group := uint32(1) << (i >> 10 & 3)
		v := c.r(rn, false)
		var reversed uint64
		for base := uint32(0); base < width/8; base += group {
			for j := uint32(0); j < group; j++ {
				reversed |= (v >> (8 * (base + j)) & 255) << (8 * (base + group - 1 - j))
			}
		}
		c.w(rd, reversed, width, false)
	case opDataTwoSource:
		a, b := c.r(rn, false)&mask(width), c.r(rm, false)&mask(width)
		var v uint64
		switch i >> 10 & 63 {
		case 2:
			if b != 0 {
				v = a / b
			}
		case 3:
			if b != 0 {
				v = uint64(int64(sext(a, width)) / int64(sext(b, width)))
			}
		case 8, 9, 10, 11:
			v = shift(a, (i>>10&63)-8, uint32(b)%width, width)
		default:
			return unsupported()
		}
		c.w(rd, v, width, false)
	case opMultiplyAdd:
		v := c.r(rn, false) * c.r(rm, false)
		a := c.r(i>>10&31, false)
		if i>>15&1 != 0 {
			v = a - v
		} else {
			v += a
		}
		c.w(rd, v, width, false)
	case opLoadStorePair: // load/store pair
		size := 4
		if i>>31 != 0 {
			size = 8
		}
		simd := i>>26&1 != 0
		if simd {
			size = 4 << uint(i>>30&3)
		} else if i>>30&3 == 3 {
			return unsupported()
		}
		if size > 16 {
			return unsupported()
		}
		base := c.r(rn, true)
		offset := sext(uint64(i>>15&127), 7) * uint64(size)
		mode := i >> 23 & 3
		addr := base + offset
		if mode == 1 {
			addr = base
		}
		load := i>>22&1 != 0
		if err := m.CheckMemory(addr, 2*size, cpu.Write); !load && err != nil {
			return effect, err
		}
		buf := c.transfer[:32]
		if load {
			if err := m.ReadMemory(addr, buf[:2*size], cpu.Read); err != nil {
				return effect, err
			}
		} else {
			c.storeReg(buf[:size], rd, simd)
			c.storeReg(buf[size:2*size], i>>10&31, simd)
			if err := m.WriteMemory(addr, buf[:2*size]); err != nil {
				return effect, err
			}
		}
		if load {
			signed := !simd && i>>30&3 == 1
			c.loadReg(buf[:size], rd, simd, signed)
			c.loadReg(buf[size:2*size], i>>10&31, simd, signed)
		}
		if mode == 1 || mode == 3 {
			c.w(rn, base+offset, 64, true)
		}
	case opLoadStore:
		size := 1 << uint(i>>30)
		simd := i>>26&1 != 0
		op := i >> 22 & 3
		if simd && op&2 != 0 {
			size = 16
		}
		if !simd && size == 8 && op >= 2 {
			return unsupported()
		}
		base := c.r(rn, true)
		addr := base
		writeback := false
		var updated uint64
		if i&0x3b000000 == 0x39000000 {
			addr += uint64(i>>10&0xfff) * uint64(size)
		} else if i>>21&1 != 0 {
			opt := i >> 13 & 7
			v := c.r(rm, false)
			switch opt {
			case 2:
				v = uint64(uint32(v))
			case 3:
			case 6:
				v = sext(v, 32)
			case 7:
			default:
				return unsupported()
			}
			if i>>12&1 != 0 {
				v *= uint64(size)
			}
			addr += v
		} else {
			offset := sext(uint64(i>>12&511), 9)
			updated = base + offset
			mode := i >> 10 & 3
			if mode != 1 {
				addr = updated
			}
			writeback = mode == 1 || mode == 3
		}
		load := op != 0
		if simd {
			load = op&1 != 0
		}
		buf := c.transfer[:16]
		if load {
			if err := m.ReadMemory(addr, buf[:size], cpu.Read); err != nil {
				return effect, err
			}
			c.loadReg(buf[:size], rd, simd, !simd && op >= 2)
			if !simd && op == 3 {
				c.w(rd, c.r(rd, false), 32, false)
			}
		} else {
			c.storeReg(buf[:size], rd, simd)
			if err := m.WriteMemory(addr, buf[:size]); err != nil {
				return effect, err
			}
		}
		if writeback {
			c.w(rn, updated, 64, true)
		}
	case opLoadLiteral:
		size := 4
		op := i >> 30
		simd := i>>26&1 != 0
		if simd {
			size <<= op
		} else if op == 1 {
			size = 8
		} else if op == 3 {
			return unsupported()
		}
		if size > 16 {
			return unsupported()
		}
		addr := c.pc + (sext(uint64(i>>5&0x7ffff), 19) << 2)
		buf := c.transfer[:16]
		if err := m.ReadMemory(addr, buf[:size], cpu.Read); err != nil {
			return effect, err
		}
		c.loadReg(buf[:size], rd, simd, !simd && op == 2)
	default:
		return unsupported()
	}
	c.pc = next
	c.AdvanceInstructions(1)
	return effect, nil
}

// AdvanceInstructions accounts for completed interpreter or accelerated units.
func (c *CPU) AdvanceInstructions(n uint64) {
	for range n {
		c.ticks++ // The deterministic virtual clock advances one tick per instruction.
		if c.pmcr&1 != 0 && c.pmcnten>>31&1 != 0 && !(c.currentEL == 4 && c.pmfilter>>31&1 != 0 || c.currentEL == 0 && c.pmfilter>>30&1 != 0) {
			c.divider++
			if c.pmcr&8 == 0 || c.divider%64 == 0 {
				previous := c.cycles
				c.cycles++
				if c.cycles == 0 || c.pmcr&64 == 0 && uint32(previous) == 0xffffffff {
					c.pmovs |= 1 << 31
				}
			}
			if c.pmcr&64 == 0 {
				c.cycles = uint64(uint32(c.cycles))
			}
		}
	}
}

func (c *CPU) storeReg(dst []byte, n uint32, simd bool) {
	if simd {
		copy(dst, c.q[n][:])
		return
	}
	v := c.r(n, false)
	for j := range dst {
		dst[j] = byte(v >> (8 * j))
	}
}
func (c *CPU) loadReg(src []byte, n uint32, simd, signed bool) {
	if simd {
		c.q[n] = [16]byte{}
		copy(c.q[n][:], src)
		return
	}
	var v uint64
	for j, b := range src {
		v |= uint64(b) << (8 * j)
	}
	if signed {
		v = sext(v, uint32(len(src)*8))
	}
	c.w(n, v, 64, false)
}

// DecodeBitMasks from the AArch64 logical-immediate/bitfield encodings.
func bitMasks(n, imms, immr, width uint32, immediate bool) (uint64, uint64, bool) {
	length := bits.Len32(n<<6|(^imms&63)) - 1
	if length < 1 {
		return 0, 0, false
	}
	esize := uint32(1) << length
	if esize > width {
		return 0, 0, false
	}
	levels := esize - 1
	s, r := imms&levels, immr&levels
	if immediate && s == levels {
		return 0, 0, false
	}
	welem := rotate(mask(s+1), r, esize)
	telem := mask(((s - r) & levels) + 1)
	var w, t uint64
	for j := uint32(0); j < width; j += esize {
		w |= welem << j
		t |= telem << j
	}
	return w, t, true
}
