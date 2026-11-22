package power

import "encoding/binary"

// x86-64 general registers in encoding order.
const (
	rAX = iota
	rCX
	rDX
	rBX
	rSP
	rBP
	rSI
	rDI
	r8
	r9
	r10
	r11
	r12
	r13
	r14
	r15
)

// x86 condition codes (the low nibble of Jcc/SETcc/CMOVcc).
const (
	ccO  = 0x0
	ccB  = 0x2 // unsigned <
	ccAE = 0x3 // unsigned >=
	ccE  = 0x4
	ccNE = 0x5
	ccBE = 0x6 // unsigned <=
	ccA  = 0x7 // unsigned >
	ccS  = 0x8
	ccNS = 0x9
	ccL  = 0xc // signed <
	ccGE = 0xd
	ccLE = 0xe
	ccG  = 0xf
)

// ALU operation numbers for the 0x01/0x81 families (the ModRM reg digit).
const (
	aluAdd = 0
	aluOr  = 1
	aluAdc = 2
	aluSbb = 3
	aluAnd = 4
	aluSub = 5
	aluXor = 6
	aluCmp = 7
)

// Shift/rotate digits for the 0xC1/0xD3 families.
const (
	shRol = 0
	shRor = 1
	shShl = 4
	shShr = 5
	shSar = 7
)

// mem is a [base + index*scale + disp] operand; index < 0 means none.
type mem struct {
	base, index, scale int
	disp               int32
}

func at(base int, disp int32) mem { return mem{base: base, index: -1, disp: disp} }

func atIndex(base, index, scale int, disp int32) mem {
	return mem{base: base, index: index, scale: scale, disp: disp}
}

// asm is a minimal x86-64 encoder for JIT blocks. Labels are byte offsets;
// forward jumps are patched by bind.
type asm struct {
	b      []byte
	fixups []fixup // rel32 positions awaiting labels
	labels []int   // label -> offset (-1 unbound)
}

type fixup struct{ label, at int }

// reset empties the assembler, keeping its buffers.
func (a *asm) reset() {
	a.b, a.fixups, a.labels = a.b[:0], a.fixups[:0], a.labels[:0]
}

func (a *asm) byte1(v ...byte) { a.b = append(a.b, v...) }
func (a *asm) imm32(v int32)   { a.b = binary.LittleEndian.AppendUint32(a.b, uint32(v)) }
func (a *asm) imm64(v uint64)  { a.b = binary.LittleEndian.AppendUint64(a.b, v) }

// rex emits a REX prefix when needed. force emits one for byte registers
// SPL/BPL/SIL/DIL.
func (a *asm) rex(w bool, reg, index, base int, force bool) {
	v := byte(0x40)
	if w {
		v |= 8
	}
	if reg&8 != 0 {
		v |= 4
	}
	if index >= 0 && index&8 != 0 {
		v |= 2
	}
	if base&8 != 0 {
		v |= 1
	}
	if v != 0x40 || force {
		a.byte1(v)
	}
}

func (a *asm) modrmReg(reg, rm int) { a.byte1(0xc0 | byte(reg&7)<<3 | byte(rm&7)) }

func (a *asm) modrmMem(reg int, m mem) {
	r := byte(reg&7) << 3
	mod := byte(0x80)
	switch {
	case m.disp == 0 && m.base&7 != rBP:
		mod = 0
	case m.disp >= -128 && m.disp <= 127:
		mod = 0x40
	}
	if m.index < 0 && m.base&7 != rSP {
		a.byte1(mod | r | byte(m.base&7))
	} else {
		idx := byte(4) // none
		scale := byte(0)
		if m.index >= 0 {
			idx = byte(m.index & 7)
			switch m.scale {
			case 2:
				scale = 1
			case 4:
				scale = 2
			case 8:
				scale = 3
			}
		}
		a.byte1(mod|r|4, scale<<6|idx<<3|byte(m.base&7))
	}
	switch mod {
	case 0x40:
		a.byte1(byte(int8(m.disp)))
	case 0x80:
		a.imm32(m.disp)
	}
}

// opRR emits op with ModRM reg=reg, rm=rm (register direct).
func (a *asm) opRR(w bool, op []byte, reg, rm int, force bool) {
	a.rex(w, reg, -1, rm, force)
	a.byte1(op...)
	a.modrmReg(reg, rm)
}

func (a *asm) opRM(w bool, op []byte, reg int, m mem, force bool) {
	a.rex(w, reg, m.index, m.base, force)
	a.byte1(op...)
	a.modrmMem(reg, m)
}

// Moves.
func (a *asm) movRR(dst, src int)    { a.opRR(true, []byte{0x8b}, dst, src, false) }
func (a *asm) movRR32(dst, src int)  { a.opRR(false, []byte{0x8b}, dst, src, false) }
func (a *asm) load64(dst int, m mem) { a.opRM(true, []byte{0x8b}, dst, m, false) }
func (a *asm) load32(dst int, m mem) { a.opRM(false, []byte{0x8b}, dst, m, false) }
func (a *asm) store64(m mem, src int) {
	a.opRM(true, []byte{0x89}, src, m, false)
}
func (a *asm) store32(m mem, src int) { a.opRM(false, []byte{0x89}, src, m, false) }
func (a *asm) store16(m mem, src int) {
	a.byte1(0x66)
	a.opRM(false, []byte{0x89}, src, m, false)
}
func (a *asm) store8(m mem, src int) { a.opRM(false, []byte{0x88}, src, m, src >= 4) }

// movzx/movsx loads.
func (a *asm) loadU8(dst int, m mem)  { a.opRM(false, []byte{0x0f, 0xb6}, dst, m, false) }
func (a *asm) loadU16(dst int, m mem) { a.opRM(false, []byte{0x0f, 0xb7}, dst, m, false) }

// movImm loads a 64-bit constant using the shortest exact encoding.
func (a *asm) movImm(dst int, v uint64) {
	switch {
	case v == 0:
		a.opRR(false, []byte{0x31}, dst, dst, false) // xor r32, r32
	case v <= 0xffffffff:
		a.rex(false, 0, -1, dst, false)
		a.byte1(0xb8 + byte(dst&7))
		a.imm32(int32(uint32(v)))
	case int64(v) >= -1<<31 && int64(v) < 1<<31:
		a.rex(true, 0, -1, dst, false)
		a.byte1(0xc7)
		a.modrmReg(0, dst)
		a.imm32(int32(int64(v)))
	default:
		a.rex(true, 0, -1, dst, false)
		a.byte1(0xb8 + byte(dst&7))
		a.imm64(v)
	}
}

// storeImm64 stores a constant into a 64-bit memory operand.
func (a *asm) storeImm64(m mem, v uint64, scratch int) {
	if int64(v) >= -1<<31 && int64(v) < 1<<31 {
		a.opRM(true, []byte{0xc7}, 0, m, false)
		a.imm32(int32(int64(v)))
		return
	}
	a.movImm(scratch, v)
	a.store64(m, scratch)
}

// ALU register/register: dst op= src.
func (a *asm) aluRR(op int, dst, src int) {
	a.opRR(true, []byte{byte(op<<3 | 1)}, src, dst, false)
}
func (a *asm) aluRR32(op int, dst, src int) {
	a.opRR(false, []byte{byte(op<<3 | 1)}, src, dst, false)
}

// aluRM: dst op= [m].
func (a *asm) aluRM(op int, dst int, m mem) {
	a.opRM(true, []byte{byte(op<<3 | 3)}, dst, m, false)
}

// aluRI: dst op= sign-extended imm32. Callers must check the range.
func (a *asm) aluRI(op int, dst int, v int32) {
	if v >= -128 && v <= 127 {
		a.opRR(true, []byte{0x83}, op, dst, false)
		a.byte1(byte(int8(v)))
		return
	}
	a.opRR(true, []byte{0x81}, op, dst, false)
	a.imm32(v)
}

func (a *asm) aluRI32(op int, dst int, v int32) {
	if v >= -128 && v <= 127 {
		a.opRR(false, []byte{0x83}, op, dst, false)
		a.byte1(byte(int8(v)))
		return
	}
	a.opRR(false, []byte{0x81}, op, dst, false)
	a.imm32(v)
}

// aluMI: [m] op= sign-extended imm32 (64-bit).
func (a *asm) aluMI(op int, m mem, v int32) {
	if v >= -128 && v <= 127 {
		a.opRM(true, []byte{0x83}, op, m, false)
		a.byte1(byte(int8(v)))
		return
	}
	a.opRM(true, []byte{0x81}, op, m, false)
	a.imm32(v)
}

// aluImm64 applies a 64-bit constant, through scratch when it does not
// fit a sign-extended imm32.
func (a *asm) aluImm64(op int, dst int, v uint64, scratch int) {
	if int64(v) >= -1<<31 && int64(v) < 1<<31 {
		a.aluRI(op, dst, int32(int64(v)))
		return
	}
	a.movImm(scratch, v)
	a.aluRR(op, dst, scratch)
}

func (a *asm) shiftRI(op int, dst int, n uint8) {
	if n == 0 {
		return
	}
	a.opRR(true, []byte{0xc1}, op, dst, false)
	a.byte1(n)
}

func (a *asm) shiftRI32(op int, dst int, n uint8) {
	if n == 0 {
		return
	}
	a.opRR(false, []byte{0xc1}, op, dst, false)
	a.byte1(n)
}

// shiftRCL shifts by CL.
func (a *asm) shiftRCL(op int, dst int) { a.opRR(true, []byte{0xd3}, op, dst, false) }

func (a *asm) testRR(x, y int)   { a.opRR(true, []byte{0x85}, y, x, false) }
func (a *asm) testRR32(x, y int) { a.opRR(false, []byte{0x85}, y, x, false) }

// testMI32 tests a 32-bit memory operand against an immediate.
func (a *asm) testMI32(m mem, v uint32) {
	a.opRM(false, []byte{0xf7}, 0, m, false)
	a.imm32(int32(v))
}

func (a *asm) testMI8(m mem, v uint8) {
	a.opRM(false, []byte{0xf6}, 0, m, false)
	a.byte1(v)
}

func (a *asm) cmpMI8(m mem, v uint8) {
	a.opRM(false, []byte{0x80}, aluCmp, m, false)
	a.byte1(v)
}

func (a *asm) setcc(cc int, dst int) { a.opRR(false, []byte{0x0f, 0x90 | byte(cc)}, 0, dst, dst >= 4) }

func (a *asm) cmov(cc int, dst, src int) {
	a.opRR(true, []byte{0x0f, 0x40 | byte(cc)}, dst, src, false)
}

func (a *asm) movzx8(dst, src int)  { a.opRR(false, []byte{0x0f, 0xb6}, dst, src, src >= 4) }
func (a *asm) movzx16(dst, src int) { a.opRR(false, []byte{0x0f, 0xb7}, dst, src, false) }
func (a *asm) movsx8(dst, src int)  { a.opRR(true, []byte{0x0f, 0xbe}, dst, src, src >= 4) }
func (a *asm) movsx16(dst, src int) { a.opRR(true, []byte{0x0f, 0xbf}, dst, src, false) }
func (a *asm) movsx32(dst, src int) { a.opRR(true, []byte{0x63}, dst, src, false) }

func (a *asm) bswap64(r int) {
	a.rex(true, 0, -1, r, false)
	a.byte1(0x0f, 0xc8+byte(r&7))
}

func (a *asm) bswap32(r int) {
	a.rex(false, 0, -1, r, false)
	a.byte1(0x0f, 0xc8+byte(r&7))
}

// rol16by8 swaps the two low bytes (rol r16, 8).
func (a *asm) rol16by8(r int) {
	a.byte1(0x66)
	a.opRR(false, []byte{0xc1}, shRol, r, false)
	a.byte1(8)
}

func (a *asm) imulRR(dst, src int) { a.opRR(true, []byte{0x0f, 0xaf}, dst, src, false) }

// mul/imul rdx:rax = rax * src.
func (a *asm) mulR(src int)  { a.opRR(true, []byte{0xf7}, 4, src, false) }
func (a *asm) imulR(src int) { a.opRR(true, []byte{0xf7}, 5, src, false) }

func (a *asm) notR(r int) { a.opRR(true, []byte{0xf7}, 2, r, false) }
func (a *asm) negR(r int) { a.opRR(true, []byte{0xf7}, 3, r, false) }

func (a *asm) lea(dst int, m mem) { a.opRM(true, []byte{0x8d}, dst, m, false) }

// bsr sets ZF when src is zero.
func (a *asm) bsr(dst, src int)   { a.opRR(true, []byte{0x0f, 0xbd}, dst, src, false) }
func (a *asm) bsr32(dst, src int) { a.opRR(false, []byte{0x0f, 0xbd}, dst, src, false) }
func (a *asm) bsf(dst, src int)   { a.opRR(true, []byte{0x0f, 0xbc}, dst, src, false) }
func (a *asm) bsf32(dst, src int) { a.opRR(false, []byte{0x0f, 0xbc}, dst, src, false) }

func (a *asm) ret() { a.byte1(0xc3) }

// Labels.
func (a *asm) newLabel() int {
	a.labels = append(a.labels, -1)
	return len(a.labels) - 1
}

func (a *asm) bind(l int) { a.labels[l] = len(a.b) }

// finish patches forward references; every referenced label must be bound.
func (a *asm) finish() {
	for _, f := range a.fixups {
		binary.LittleEndian.PutUint32(a.b[f.at:], uint32(int32(a.labels[f.label]-(f.at+4))))
	}
	a.fixups = a.fixups[:0]
}

func (a *asm) rel32(l int) {
	if off := a.labels[l]; off >= 0 {
		a.imm32(int32(off - (len(a.b) + 4)))
		return
	}
	a.fixups = append(a.fixups, fixup{label: l, at: len(a.b)})
	a.imm32(0)
}

func (a *asm) jcc(cc int, l int) {
	a.byte1(0x0f, 0x80|byte(cc))
	a.rel32(l)
}

func (a *asm) jmp(l int) {
	a.byte1(0xe9)
	a.rel32(l)
}
