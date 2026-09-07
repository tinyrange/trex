// Package amd64 implements bounded in-process AMD64 instruction execution.
// Windows loading and API semantics are intentionally outside the processor.
package amd64

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"strings"

	"github.com/tinyrange/trex/emulator/cpu"
	"golang.org/x/arch/x86/x86asm"
)

const (
	flagCarry     = uint64(1 << 0)
	flagParity    = uint64(1 << 2)
	flagZero      = uint64(1 << 6)
	flagSign      = uint64(1 << 7)
	flagDirection = uint64(1 << 10)
	flagOverflow  = uint64(1 << 11)
)

// CPU is a value-type execution context, so saving it does not alias mutable
// register state. Memory and environment state are saved by their owners.
type CPU struct {
	registers [16]uint64
	xmm       [16][16]byte
	rip       uint64
	flags     uint64
	fsBase    uint64
	gsBase    uint64
	mxcsr     uint32
	mxcsrSet  bool
}

var _ cpu.Processor = (*CPU)(nil)

func (c *CPU) Clone() cpu.Processor { clone := *c; return &clone }

func (*CPU) Architecture() cpu.Architecture { return cpu.Architecture{Name: "amd64", PointerSize: 8} }
func (c *CPU) PC() uint64                   { return c.rip }
func (c *CPU) SetPC(address uint64)         { c.rip = address }

func (c *CPU) readMXCSR() uint64 {
	if !c.mxcsrSet {
		return 0x1f80 // Architectural reset state: masked SSE exceptions.
	}
	return uint64(c.mxcsr)
}

func (c *CPU) setMXCSR(value uint64) error {
	if value&^uint64(0xffff) != 0 {
		return fmt.Errorf("amd64: MXCSR has reserved bits set: %#x", value)
	}
	c.mxcsr, c.mxcsrSet = uint32(value), true
	return nil
}

type alias struct{ index, width, shift int }

func registerAlias(reg x86asm.Reg) (alias, bool) {
	switch {
	case reg >= x86asm.RAX && reg <= x86asm.R15:
		return alias{int(reg - x86asm.RAX), 8, 0}, true
	case reg >= x86asm.EAX && reg <= x86asm.R15L:
		return alias{int(reg - x86asm.EAX), 4, 0}, true
	case reg >= x86asm.AX && reg <= x86asm.R15W:
		return alias{int(reg - x86asm.AX), 2, 0}, true
	case reg >= x86asm.AL && reg <= x86asm.BL:
		return alias{int(reg - x86asm.AL), 1, 0}, true
	case reg >= x86asm.AH && reg <= x86asm.BH:
		return alias{int(reg - x86asm.AH), 1, 8}, true
	case reg >= x86asm.SPB && reg <= x86asm.R15B:
		return alias{int(reg-x86asm.SPB) + 4, 1, 0}, true
	}
	return alias{}, false
}

func mask(width int) uint64 { return math.MaxUint64 >> (64 - width*8) }

func (c *CPU) reg(reg x86asm.Reg) (uint64, error) {
	if reg == x86asm.RIP {
		return c.rip, nil
	}
	if reg == x86asm.EIP {
		return uint64(uint32(c.rip)), nil
	}
	a, ok := registerAlias(reg)
	if !ok {
		return 0, fmt.Errorf("amd64: unsupported register %s", reg)
	}
	return c.registers[a.index] >> a.shift & mask(a.width), nil
}

func (c *CPU) setReg(reg x86asm.Reg, value uint64) error {
	a, ok := registerAlias(reg)
	if !ok {
		return fmt.Errorf("amd64: unsupported register %s", reg)
	}
	if a.width >= 4 {
		// A 32-bit register write clears the upper half in long mode.
		c.registers[a.index] = value & mask(a.width)
	} else {
		m := mask(a.width) << a.shift
		c.registers[a.index] = c.registers[a.index] & ^m | (value<<a.shift)&m
	}
	return nil
}

var namedRegisters = func() map[string]x86asm.Reg {
	result := make(map[string]x86asm.Reg)
	for reg := x86asm.AL; reg <= x86asm.R15; reg++ {
		if _, ok := registerAlias(reg); ok {
			result[strings.ToLower(reg.String())] = reg
		}
	}
	// x86asm uses SPB and R8L; also accept conventional assembler spellings.
	for name, reg := range map[string]x86asm.Reg{"spl": x86asm.SPB, "bpl": x86asm.BPB, "sil": x86asm.SIB, "dil": x86asm.DIB} {
		result[name] = reg
	}
	for i := 8; i < 16; i++ {
		result[fmt.Sprintf("r%dd", i)] = x86asm.R8L + x86asm.Reg(i-8)
	}
	return result
}()

func (c *CPU) Register(name string) (uint64, error) {
	switch strings.ToLower(name) {
	case "rip":
		return c.rip, nil
	case "rflags":
		return c.flags | 2, nil
	case "mxcsr":
		return c.readMXCSR(), nil
	case "fs_base":
		return c.fsBase, nil
	case "gs_base":
		return c.gsBase, nil
	}
	if r, ok := namedRegisters[strings.ToLower(name)]; ok {
		return c.reg(r)
	}
	return 0, fmt.Errorf("amd64: unknown register %q", name)
}

func (c *CPU) SetRegister(name string, value uint64) error {
	switch strings.ToLower(name) {
	case "rip":
		c.rip = value
		return nil
	case "rflags":
		c.flags = value
		return nil
	case "mxcsr":
		return c.setMXCSR(value)
	case "fs_base":
		c.fsBase = value
		return nil
	case "gs_base":
		c.gsBase = value
		return nil
	}
	if r, ok := namedRegisters[strings.ToLower(name)]; ok {
		return c.setReg(r, value)
	}
	return fmt.Errorf("amd64: unknown register %q", name)
}

func (c *CPU) address(mem x86asm.Mem, next uint64, addressSize int) (uint64, error) {
	value := uint64(mem.Disp)
	// x86asm preserves disp32 as an unsigned value. Address displacements
	// added to a register (including RIP) are signed in long mode.
	if (mem.Base != 0 || mem.Index != 0) && mem.Disp >= 0 && mem.Disp <= math.MaxUint32 {
		value = uint64(int64(int32(mem.Disp)))
	}
	if mem.Base == x86asm.RIP || mem.Base == x86asm.EIP {
		value += next
	} else if mem.Base != 0 {
		base, err := c.reg(mem.Base)
		if err != nil {
			return 0, err
		}
		value += base
	}
	if mem.Index != 0 {
		index, err := c.reg(mem.Index)
		if err != nil {
			return 0, err
		}
		value += index * uint64(mem.Scale)
	}
	if addressSize == 32 {
		value = uint64(uint32(value))
	}
	switch mem.Segment {
	case x86asm.FS:
		value += c.fsBase
	case x86asm.GS:
		value += c.gsBase
	}
	return value, nil
}

func readWord(memory cpu.Memory, address uint64, width int) (uint64, error) {
	if width != 1 && width != 2 && width != 4 && width != 8 {
		return 0, fmt.Errorf("amd64: unsupported scalar width %d", width)
	}
	var data [8]byte
	if err := memory.ReadMemory(address, data[:width], cpu.Read); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data[:]), nil
}

func writeWord(memory cpu.Memory, address uint64, width int, value uint64) error {
	if width != 1 && width != 2 && width != 4 && width != 8 {
		return fmt.Errorf("amd64: unsupported scalar width %d", width)
	}
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	return memory.WriteMemory(address, data[:width])
}

func operandWidth(arg x86asm.Arg, inst x86asm.Inst) int {
	if r, ok := arg.(x86asm.Reg); ok {
		if a, ok := registerAlias(r); ok {
			return a.width
		}
	}
	if _, ok := arg.(x86asm.Mem); ok && inst.MemBytes != 0 {
		return inst.MemBytes
	}
	return inst.DataSize / 8
}

func (c *CPU) readOperand(memory cpu.Memory, arg x86asm.Arg, inst x86asm.Inst, next uint64, width int) (uint64, error) {
	switch a := arg.(type) {
	case x86asm.Reg:
		return c.reg(a)
	case x86asm.Imm:
		return uint64(a), nil
	case x86asm.Rel:
		return next + uint64(a), nil
	case x86asm.Mem:
		address, err := c.address(a, next, inst.AddrSize)
		if err != nil {
			return 0, err
		}
		return readWord(memory, address, width)
	}
	return 0, fmt.Errorf("amd64: unsupported operand %v", arg)
}

func (c *CPU) writeOperand(memory cpu.Memory, arg x86asm.Arg, inst x86asm.Inst, next uint64, width int, value uint64) error {
	switch a := arg.(type) {
	case x86asm.Reg:
		return c.setReg(a, value)
	case x86asm.Mem:
		address, err := c.address(a, next, inst.AddrSize)
		if err != nil {
			return err
		}
		return writeWord(memory, address, width, value)
	}
	return fmt.Errorf("amd64: unsupported destination %v", arg)
}

func (c *CPU) flag(flag uint64, set bool) {
	c.flags &^= flag
	if set {
		c.flags |= flag
	}
}
func (c *CPU) resultFlags(value uint64, width int) {
	value &= mask(width)
	c.flag(flagZero, value == 0)
	c.flag(flagSign, value&(uint64(1)<<(width*8-1)) != 0)
	c.flag(flagParity, bits.OnesCount8(uint8(value))%2 == 0)
}

func (c *CPU) arithmetic(left, right uint64, width int, subtract, carry bool) uint64 {
	m := mask(width)
	left &= m
	right &= m
	inputCarry := uint64(0)
	if carry {
		inputCarry = 1
	}
	var result, outputCarry uint64
	if subtract {
		result, outputCarry = bits.Sub64(left, right, inputCarry)
		c.flag(flagOverflow, (left^right)&(left^result)&(uint64(1)<<(width*8-1)) != 0)
	} else {
		result, outputCarry = bits.Add64(left, right, inputCarry)
		c.flag(flagOverflow, ^(left^right)&(left^result)&(uint64(1)<<(width*8-1)) != 0)
	}
	c.flag(flagCarry, outputCarry != 0 || (!subtract && result > m))
	c.resultFlags(result, width)
	return result & m
}

func (c *CPU) condition(op x86asm.Op) (bool, bool) {
	cf, zf, sf, of, pf := c.flags&flagCarry != 0, c.flags&flagZero != 0, c.flags&flagSign != 0, c.flags&flagOverflow != 0, c.flags&flagParity != 0
	switch op {
	case x86asm.JE, x86asm.SETE, x86asm.CMOVE:
		return zf, true
	case x86asm.JNE, x86asm.SETNE, x86asm.CMOVNE:
		return !zf, true
	case x86asm.JB, x86asm.SETB, x86asm.CMOVB:
		return cf, true
	case x86asm.JAE, x86asm.SETAE, x86asm.CMOVAE:
		return !cf, true
	case x86asm.JBE, x86asm.SETBE, x86asm.CMOVBE:
		return cf || zf, true
	case x86asm.JA, x86asm.SETA, x86asm.CMOVA:
		return !cf && !zf, true
	case x86asm.JL, x86asm.SETL, x86asm.CMOVL:
		return sf != of, true
	case x86asm.JGE, x86asm.SETGE, x86asm.CMOVGE:
		return sf == of, true
	case x86asm.JLE, x86asm.SETLE, x86asm.CMOVLE:
		return zf || sf != of, true
	case x86asm.JG, x86asm.SETG, x86asm.CMOVG:
		return !zf && sf == of, true
	case x86asm.JS, x86asm.SETS, x86asm.CMOVS:
		return sf, true
	case x86asm.JNS, x86asm.SETNS, x86asm.CMOVNS:
		return !sf, true
	case x86asm.JO, x86asm.SETO, x86asm.CMOVO:
		return of, true
	case x86asm.JNO, x86asm.SETNO, x86asm.CMOVNO:
		return !of, true
	case x86asm.JP, x86asm.SETP, x86asm.CMOVP:
		return pf, true
	case x86asm.JNP, x86asm.SETNP, x86asm.CMOVNP:
		return !pf, true
	}
	return false, false
}

func (c *CPU) push(memory cpu.Memory, value uint64, width int) error {
	sp := c.registers[x86asm.RSP-x86asm.RAX] - uint64(width)
	if err := writeWord(memory, sp, width, value); err != nil {
		return err
	}
	c.registers[x86asm.RSP-x86asm.RAX] = sp
	return nil
}

// Step never loops over guest instructions. Unsupported instructions produce
// a precise error at the current RIP rather than being treated as no-ops.
func (c *CPU) Step(memory cpu.Memory) (cpu.Effect, error) {
	var code [15]byte
	count := 0
	for count < len(code) {
		if c.rip > math.MaxUint64-uint64(count) {
			break
		}
		if err := memory.ReadMemory(c.rip+uint64(count), code[count:count+1], cpu.Execute); err != nil {
			if count == 0 {
				return cpu.Continue, err
			}
			break
		}
		count++
	}
	inst, err := x86asm.Decode(code[:count], 64)
	if err != nil || inst.Op == 0 {
		return cpu.Continue, fmt.Errorf("amd64: decode at %#x: %v", c.rip, err)
	}
	next := c.rip + uint64(inst.Len)
	width := operandWidth(inst.Args[0], inst)
	read := func(arg x86asm.Arg, size int) (uint64, error) { return c.readOperand(memory, arg, inst, next, size) }
	write := func(value uint64) error { return c.writeOperand(memory, inst.Args[0], inst, next, width, value) }
	effect := cpu.Continue
	if take, ok := c.condition(inst.Op); ok {
		name := inst.Op.String()
		switch {
		case strings.HasPrefix(name, "J"):
			if take {
				next, err = read(inst.Args[0], 8)
			}
		case strings.HasPrefix(name, "SET"):
			value := uint64(0)
			if take {
				value = 1
			}
			err = write(value)
		default:
			// CMOV reads its source even when the condition is false.
			var value uint64
			value, err = read(inst.Args[1], width)
			if err == nil && take {
				err = write(value)
			}
		}
	} else {
		switch inst.Op {
		case x86asm.STMXCSR:
			err = c.writeOperand(memory, inst.Args[0], inst, next, 4, c.readMXCSR())
		case x86asm.LDMXCSR:
			var value uint64
			value, err = read(inst.Args[0], 4)
			if err == nil {
				err = c.setMXCSR(value)
			}
		case x86asm.CMPXCHG:
			// An instruction step is indivisible in the execution scheduler,
			// including LOCKed read/modify/write operations. CMPXCHG performs
			// a destination write even when the comparison fails.
			destination, readErr := read(inst.Args[0], width)
			if readErr != nil {
				err = readErr
				break
			}
			source, readErr := read(inst.Args[1], width)
			if readErr != nil {
				err = readErr
				break
			}
			accumulator := c.registers[0] & mask(width)
			value := destination
			if accumulator == destination {
				value = source
			}
			if err = write(value); err != nil {
				break
			}
			c.arithmetic(accumulator, destination, width, true, false)
			if accumulator != destination {
				reg := x86asm.RAX
				switch width {
				case 1:
					reg = x86asm.AL
				case 2:
					reg = x86asm.AX
				case 4:
					reg = x86asm.EAX
				}
				err = c.setReg(reg, destination)
			}
		case x86asm.CBW:
			err = c.setReg(x86asm.AX, uint64(int64(int8(c.registers[0]))))
		case x86asm.CWDE:
			err = c.setReg(x86asm.EAX, uint64(int64(int16(c.registers[0]))))
		case x86asm.CDQE:
			err = c.setReg(x86asm.RAX, uint64(int64(int32(c.registers[0]))))
		case x86asm.CWD, x86asm.CDQ, x86asm.CQO:
			reg, width := x86asm.RDX, 8
			if inst.Op == x86asm.CWD {
				reg, width = x86asm.DX, 2
			} else if inst.Op == x86asm.CDQ {
				reg, width = x86asm.EDX, 4
			}
			value := uint64(0)
			if c.registers[0]&(uint64(1)<<(width*8-1)) != 0 {
				value = mask(width)
			}
			err = c.setReg(reg, value)
		case x86asm.MUL, x86asm.IMUL:
			var left, right uint64
			one := inst.Args[1] == nil
			if one {
				left = c.registers[0]
				right, err = read(inst.Args[0], width)
			} else if inst.Args[2] == nil {
				left, err = read(inst.Args[0], width)
				if err == nil {
					right, err = read(inst.Args[1], width)
				}
			} else {
				left, err = read(inst.Args[1], width)
				if err == nil {
					right, err = read(inst.Args[2], width)
				}
			}
			if err != nil {
				break
			}
			left &= mask(width)
			right &= mask(width)
			var high, low uint64
			if width == 8 {
				high, low = bits.Mul64(left, right)
				if inst.Op == x86asm.IMUL {
					if left>>63 != 0 {
						high -= right
					}
					if right>>63 != 0 {
						high -= left
					}
				}
			} else {
				product := left * right
				if inst.Op == x86asm.IMUL {
					shift := 64 - width*8
					product = uint64((int64(left<<shift) >> shift) * (int64(right<<shift) >> shift))
				}
				low, high = product&mask(width), (product>>(width*8))&mask(width)
			}
			expectedHigh := uint64(0)
			if inst.Op == x86asm.IMUL && low&(uint64(1)<<(width*8-1)) != 0 {
				expectedHigh = mask(width)
			}
			c.flag(flagCarry, high != expectedHigh)
			c.flag(flagOverflow, high != expectedHigh)
			if !one {
				err = write(low)
				break
			}
			if width == 1 {
				err = c.setReg(x86asm.AX, low|high<<8)
				break
			}
			lowReg, highReg := x86asm.RAX, x86asm.RDX
			if width == 2 {
				lowReg, highReg = x86asm.AX, x86asm.DX
			} else if width == 4 {
				lowReg, highReg = x86asm.EAX, x86asm.EDX
			}
			if err = c.setReg(lowReg, low); err == nil {
				err = c.setReg(highReg, high)
			}
		case x86asm.DIV, x86asm.IDIV:
			var divisor uint64
			divisor, err = read(inst.Args[0], width)
			if err != nil {
				break
			}
			divisor &= mask(width)
			if divisor == 0 {
				err = fmt.Errorf("integer divide by zero")
				break
			}
			var quotient, remainder uint64
			highWord, lowWord := c.registers[x86asm.RDX-x86asm.RAX]&mask(width), c.registers[0]&mask(width)
			if width == 1 {
				highWord = (c.registers[0] >> 8) & 0xff
			}
			negativeDividend, negativeQuotient := false, false
			if inst.Op == x86asm.IDIV {
				sign := uint64(1) << (width*8 - 1)
				negativeDividend = highWord&sign != 0
				negativeDivisor := divisor&sign != 0
				negativeQuotient = negativeDividend != negativeDivisor
				if negativeDividend {
					lowWord = -lowWord & mask(width)
					highWord = ^highWord & mask(width)
					if lowWord == 0 {
						highWord = (highWord + 1) & mask(width)
					}
				}
				if negativeDivisor {
					divisor = -divisor & mask(width)
				}
			}
			if width == 8 {
				if highWord >= divisor {
					err = fmt.Errorf("integer divide quotient overflow")
					break
				}
				quotient, remainder = bits.Div64(highWord, lowWord, divisor)
			} else {
				dividend := lowWord | highWord<<(width*8)
				quotient, remainder = dividend/divisor, dividend%divisor
				if quotient > mask(width) {
					err = fmt.Errorf("integer divide quotient overflow")
					break
				}
			}
			if inst.Op == x86asm.IDIV {
				limit := uint64(1) << (width*8 - 1)
				if !negativeQuotient {
					limit--
				}
				if quotient > limit {
					err = fmt.Errorf("integer divide quotient overflow")
					break
				}
				if negativeQuotient {
					quotient = -quotient & mask(width)
				}
				if negativeDividend {
					remainder = -remainder & mask(width)
				}
			}
			low, high := x86asm.RAX, x86asm.RDX
			switch width {
			case 1:
				low, high = x86asm.AL, x86asm.AH
			case 2:
				low, high = x86asm.AX, x86asm.DX
			case 4:
				low, high = x86asm.EAX, x86asm.EDX
			}
			if err = c.setReg(low, quotient); err == nil {
				err = c.setReg(high, remainder)
			}
		case x86asm.BT, x86asm.BTC:
			var value, index uint64
			var memoryAddress uint64
			memoryOperand := false
			index, err = read(inst.Args[1], width)
			if err != nil {
				break
			}
			if mem, ok := inst.Args[0].(x86asm.Mem); ok {
				var address uint64
				address, err = c.address(mem, next, inst.AddrSize)
				if err != nil {
					break
				}
				if _, register := inst.Args[1].(x86asm.Reg); register {
					indexWidth := operandWidth(inst.Args[1], inst)
					signed := int64(index<<(64-indexWidth*8)) >> (64 - indexWidth*8)
					address += uint64(signed>>bits.TrailingZeros(uint(width*8))) * uint64(width)
				}
				value, err = readWord(memory, address, width)
				memoryAddress, memoryOperand = address, true
			} else {
				value, err = read(inst.Args[0], width)
			}
			if err == nil {
				bit := uint64(1) << (index % uint64(width*8))
				if inst.Op == x86asm.BTC {
					if memoryOperand {
						err = writeWord(memory, memoryAddress, width, value^bit)
					} else {
						err = write(value ^ bit)
					}
				}
				if err == nil {
					c.flag(flagCarry, value&bit != 0)
				}
			}
		case x86asm.ROL, x86asm.ROR:
			var value, count uint64
			value, err = read(inst.Args[0], width)
			if err != nil {
				break
			}
			count, err = read(inst.Args[1], 1)
			if err != nil {
				break
			}
			if width == 8 {
				count &= 63
			} else {
				count &= 31
			}
			maskedCount := count
			bitWidth := uint64(width * 8)
			count %= bitWidth
			if count == 0 {
				break
			}
			value &= mask(width)
			if inst.Op == x86asm.ROL {
				value = (value<<count | value>>(bitWidth-count)) & mask(width)
				c.flag(flagCarry, value&1 != 0)
			} else {
				value = (value>>count | value<<(bitWidth-count)) & mask(width)
				c.flag(flagCarry, value>>(bitWidth-1) != 0)
			}
			if maskedCount == 1 {
				if inst.Op == x86asm.ROL {
					c.flag(flagOverflow, (value>>(bitWidth-1) != 0) != (c.flags&flagCarry != 0))
				} else {
					c.flag(flagOverflow, ((value>>(bitWidth-1))^(value>>(bitWidth-2)))&1 != 0)
				}
			}
			err = write(value)
		case x86asm.SAR, x86asm.SHR, x86asm.SHL:
			var value, count uint64
			value, err = read(inst.Args[0], width)
			if err != nil {
				break
			}
			count, err = read(inst.Args[1], 1)
			if err != nil {
				break
			}
			if width == 8 {
				count &= 63
			} else {
				count &= 31
			}
			if count == 0 {
				break
			}
			value &= mask(width)
			bitWidth := uint64(width * 8)
			original := value
			switch inst.Op {
			case x86asm.SAR:
				value = uint64((int64(value<<(64-bitWidth)) >> (64 - bitWidth)) >> count)
				c.flag(flagCarry, original>>min(count-1, bitWidth-1)&1 != 0)
			case x86asm.SHR:
				value >>= count
				c.flag(flagCarry, count <= bitWidth && original>>(count-1)&1 != 0)
			case x86asm.SHL:
				value <<= count
				c.flag(flagCarry, count <= bitWidth && original>>(bitWidth-count)&1 != 0)
			}
			if count == 1 {
				signBit := uint64(1) << (bitWidth - 1)
				switch inst.Op {
				case x86asm.SAR:
					c.flag(flagOverflow, false)
				case x86asm.SHR:
					c.flag(flagOverflow, original&signBit != 0)
				case x86asm.SHL:
					c.flag(flagOverflow, (value&signBit != 0) != (c.flags&flagCarry != 0))
				}
			}
			c.resultFlags(value, width)
			err = write(value)
		case x86asm.MOVDQA, x86asm.MOVDQU, x86asm.MOVAPS, x86asm.MOVUPS:
			var value [16]byte
			aligned := inst.Op == x86asm.MOVDQA || inst.Op == x86asm.MOVAPS
			switch source := inst.Args[1].(type) {
			case x86asm.Reg:
				if source < x86asm.X0 || source > x86asm.X15 {
					err = fmt.Errorf("invalid vector source %s", source)
					break
				}
				value = c.xmm[source-x86asm.X0]
			case x86asm.Mem:
				var address uint64
				address, err = c.address(source, next, inst.AddrSize)
				if err == nil && aligned && address&15 != 0 {
					err = fmt.Errorf("unaligned vector read at %#x", address)
				}
				if err == nil {
					err = memory.ReadMemory(address, value[:], cpu.Read)
				}
			default:
				err = fmt.Errorf("invalid vector source %v", source)
			}
			if err != nil {
				break
			}
			switch destination := inst.Args[0].(type) {
			case x86asm.Reg:
				if destination < x86asm.X0 || destination > x86asm.X15 {
					err = fmt.Errorf("invalid vector destination %s", destination)
					break
				}
				c.xmm[destination-x86asm.X0] = value
			case x86asm.Mem:
				var address uint64
				address, err = c.address(destination, next, inst.AddrSize)
				if err == nil && aligned && address&15 != 0 {
					err = fmt.Errorf("unaligned vector write at %#x", address)
				}
				if err == nil {
					err = memory.WriteMemory(address, value[:])
				}
			default:
				err = fmt.Errorf("invalid vector destination %v", destination)
			}
		case x86asm.SCASB, x86asm.SCASW, x86asm.SCASD, x86asm.SCASQ,
			x86asm.STOSB, x86asm.STOSW, x86asm.STOSD, x86asm.STOSQ,
			x86asm.CMPSB, x86asm.CMPSW, x86asm.CMPSD, x86asm.CMPSQ:
			store := inst.Op == x86asm.STOSB || inst.Op == x86asm.STOSW || inst.Op == x86asm.STOSD || inst.Op == x86asm.STOSQ
			compareStrings := inst.Op == x86asm.CMPSB || inst.Op == x86asm.CMPSW || inst.Op == x86asm.CMPSD || inst.Op == x86asm.CMPSQ
			width = 1
			switch inst.Op {
			case x86asm.SCASW, x86asm.STOSW, x86asm.CMPSW:
				width = 2
			case x86asm.SCASD, x86asm.STOSD, x86asm.CMPSD:
				width = 4
			case x86asm.SCASQ, x86asm.STOSQ, x86asm.CMPSQ:
				width = 8
			}
			repeat, whileEqual := false, false
			for _, prefix := range inst.Prefix {
				switch prefix & 0xff {
				case x86asm.PrefixREP:
					repeat, whileEqual = true, true
				case x86asm.PrefixREPN:
					repeat = true
				}
			}
			countReg, indexReg := x86asm.RCX, x86asm.RDI
			if inst.AddrSize == 32 {
				countReg, indexReg = x86asm.ECX, x86asm.EDI
			}
			count, _ := c.reg(countReg)
			if repeat && count == 0 {
				break
			}
			address, _ := c.reg(indexReg)
			if store {
				err = writeWord(memory, address, width, c.registers[0])
			} else {
				var value uint64
				value, err = readWord(memory, address, width)
				left := c.registers[0]
				if err == nil && compareStrings {
					left, err = read(inst.Args[0], width)
				}
				if err == nil {
					c.arithmetic(left, value, width, true, false)
				}
			}
			if err != nil {
				break
			}
			if c.flags&flagDirection != 0 {
				address -= uint64(width)
			} else {
				address += uint64(width)
			}
			if err = c.setReg(indexReg, address); err != nil {
				break
			}
			if compareStrings {
				sourceReg := x86asm.RSI
				if inst.AddrSize == 32 {
					sourceReg = x86asm.ESI
				}
				source, _ := c.reg(sourceReg)
				if c.flags&flagDirection != 0 {
					source -= uint64(width)
				} else {
					source += uint64(width)
				}
				if err = c.setReg(sourceReg, source); err != nil {
					break
				}
			}
			if repeat {
				count--
				if err = c.setReg(countReg, count); err != nil {
					break
				}
				// One element consumes one execution step. Retaining RIP
				// makes long repeats budgeted and resumable without hidden state.
				if count != 0 && (store || (c.flags&flagZero != 0) == whileEqual) {
					next = c.rip
				}
			}
		case x86asm.NOP:
		case x86asm.BSWAP:
			var value uint64
			value, err = read(inst.Args[0], width)
			if err == nil {
				switch width {
				case 4:
					err = write(uint64(bits.ReverseBytes32(uint32(value))))
				case 8:
					err = write(bits.ReverseBytes64(value))
				default:
					err = fmt.Errorf("undefined BSWAP operand width %d", width)
				}
			}
		case x86asm.HLT:
			effect = cpu.Halt
		case x86asm.CLD:
			c.flags &^= flagDirection
		case x86asm.STD:
			c.flags |= flagDirection
		case x86asm.CLC:
			c.flags &^= flagCarry
		case x86asm.STC:
			c.flags |= flagCarry
		case x86asm.CMC:
			c.flags ^= flagCarry
		case x86asm.MOV, x86asm.MOVZX, x86asm.MOVSX, x86asm.MOVSXD:
			sourceWidth := width
			if inst.Op != x86asm.MOV {
				sourceWidth = operandWidth(inst.Args[1], inst)
			}
			var value uint64
			value, err = read(inst.Args[1], sourceWidth)
			if err == nil {
				if inst.Op == x86asm.MOVSX || inst.Op == x86asm.MOVSXD {
					value = uint64(int64(value<<(64-sourceWidth*8)) >> (64 - sourceWidth*8))
				}
				err = write(value)
			}
		case x86asm.LEA:
			mem, ok := inst.Args[1].(x86asm.Mem)
			if !ok {
				err = fmt.Errorf("invalid LEA operand")
				break
			}
			mem.Segment = 0
			var value uint64
			value, err = c.address(mem, next, inst.AddrSize)
			if err == nil {
				err = write(value)
			}
		case x86asm.ADD, x86asm.ADC, x86asm.SUB, x86asm.SBB, x86asm.CMP, x86asm.AND, x86asm.OR, x86asm.XOR, x86asm.TEST:
			var left, right uint64
			left, err = read(inst.Args[0], width)
			if err != nil {
				break
			}
			right, err = read(inst.Args[1], width)
			if err != nil {
				break
			}
			var value uint64
			switch inst.Op {
			case x86asm.ADD, x86asm.ADC:
				value = c.arithmetic(left, right, width, false, inst.Op == x86asm.ADC && c.flags&flagCarry != 0)
			case x86asm.SUB, x86asm.SBB, x86asm.CMP:
				value = c.arithmetic(left, right, width, true, inst.Op == x86asm.SBB && c.flags&flagCarry != 0)
			default:
				switch inst.Op {
				case x86asm.AND, x86asm.TEST:
					value = left & right
				case x86asm.OR:
					value = left | right
				case x86asm.XOR:
					value = left ^ right
				}
				c.flags &^= flagCarry | flagOverflow
				c.resultFlags(value, width)
			}
			if inst.Op != x86asm.CMP && inst.Op != x86asm.TEST {
				err = write(value)
			}
		case x86asm.INC, x86asm.DEC, x86asm.NEG, x86asm.NOT:
			var value uint64
			value, err = read(inst.Args[0], width)
			if err != nil {
				break
			}
			carry := c.flags & flagCarry
			switch inst.Op {
			case x86asm.INC:
				value = c.arithmetic(value, 1, width, false, false)
				c.flags = c.flags & ^flagCarry | carry
			case x86asm.DEC:
				value = c.arithmetic(value, 1, width, true, false)
				c.flags = c.flags & ^flagCarry | carry
			case x86asm.NEG:
				value = c.arithmetic(0, value, width, true, false)
			case x86asm.NOT:
				value = ^value
			}
			err = write(value)
		case x86asm.POPF, x86asm.POPFQ:
			width := 8
			if inst.Op == x86asm.POPF {
				width = 2
			}
			sp := c.registers[x86asm.RSP-x86asm.RAX]
			var value uint64
			value, err = readWord(memory, sp, width)
			if err == nil {
				// This is a user-mode processor (CPL 3). IOPL and the
				// virtualization flags cannot be changed by POPF; IF is
				// writable only with IOPL 3. RF is cleared, not restored.
				writable := uint64(1<<0 | 1<<2 | 1<<4 | 1<<6 | 1<<7 | 1<<8 | 1<<10 | 1<<11 | 1<<14)
				if c.flags>>12&3 == 3 {
					writable |= 1 << 9
				}
				if width == 8 {
					writable |= 1<<18 | 1<<21
				}
				c.flags = (c.flags &^ (writable | 1<<16)) | (value & writable)
				c.registers[x86asm.RSP-x86asm.RAX] = sp + uint64(width)
			}
		case x86asm.PUSHF, x86asm.PUSHFQ:
			width = 8
			if inst.Op == x86asm.PUSHF {
				width = 2
			}
			// PUSHFQ's saved image clears RF and VM, without changing
			// the live flags. Bit 1 is architecturally fixed at one.
			err = c.push(memory, (c.flags|2)&^uint64((1<<16)|(1<<17)), width)
		case x86asm.ENTER:
			width = 8
			if inst.DataSize == 16 {
				width = 2
			}
			// Keep architectural registers unchanged if any stack access faults.
			frame := *c
			bp := frame.registers[x86asm.RBP-x86asm.RAX]
			err = frame.push(memory, bp, width)
			framePointer := frame.registers[x86asm.RSP-x86asm.RAX]
			level := uint64(inst.Args[1].(x86asm.Imm)) & 31
			for i := uint64(1); i < level && err == nil; i++ {
				bp -= uint64(width)
				var value uint64
				value, err = readWord(memory, bp, width)
				if err == nil {
					err = frame.push(memory, value, width)
				}
			}
			if level != 0 && err == nil {
				err = frame.push(memory, framePointer, width)
			}
			if err == nil {
				sp := frame.registers[x86asm.RSP-x86asm.RAX] - uint64(uint16(inst.Args[0].(x86asm.Imm)))
				// ENTER checks that the final stack address is writable even
				// though allocating locals does not write their contents.
				err = memory.CheckMemory(sp, 1, cpu.Write)
				if err == nil {
					c.registers[x86asm.RSP-x86asm.RAX] = sp
					if width == 2 {
						c.registers[x86asm.RBP-x86asm.RAX] = (c.registers[x86asm.RBP-x86asm.RAX] &^ 0xffff) | (framePointer & 0xffff)
					} else {
						c.registers[x86asm.RBP-x86asm.RAX] = framePointer
					}
				}
			}
		case x86asm.LEAVE:
			width = 8
			if inst.DataSize == 16 {
				width = 2
			}
			sp := c.registers[x86asm.RBP-x86asm.RAX]
			var value uint64
			value, err = readWord(memory, sp, width)
			if err == nil {
				c.registers[x86asm.RSP-x86asm.RAX] = sp + uint64(width)
				if width == 2 {
					value = (sp &^ 0xffff) | value
				}
				c.registers[x86asm.RBP-x86asm.RAX] = value
			}
		case x86asm.PUSH:
			width = 8
			if inst.DataSize == 16 {
				width = 2
			}
			var value uint64
			value, err = read(inst.Args[0], width)
			if err == nil {
				err = c.push(memory, value, width)
			}
		case x86asm.POP:
			width = 8
			if inst.DataSize == 16 {
				width = 2
			}
			sp := c.registers[x86asm.RSP-x86asm.RAX]
			var value uint64
			value, err = readWord(memory, sp, width)
			if err == nil {
				c.registers[x86asm.RSP-x86asm.RAX] = sp + uint64(width)
				err = write(value)
				if err != nil {
					c.registers[x86asm.RSP-x86asm.RAX] = sp
				}
			}
		case x86asm.CALL, x86asm.JMP:
			var target uint64
			target, err = read(inst.Args[0], 8)
			if err == nil && inst.Op == x86asm.CALL {
				err = c.push(memory, next, 8)
				effect = cpu.Call
			}
			if err == nil {
				next = target
			}
		case x86asm.RET:
			sp := c.registers[x86asm.RSP-x86asm.RAX]
			next, err = readWord(memory, sp, 8)
			if err == nil {
				sp += 8
				if immediate, ok := inst.Args[0].(x86asm.Imm); ok {
					sp += uint64(immediate)
				}
				c.registers[x86asm.RSP-x86asm.RAX] = sp
				effect = cpu.Return
			}
		default:
			err = fmt.Errorf("unsupported instruction %s", inst)
		}
	}
	if err != nil {
		return cpu.Continue, fmt.Errorf("amd64: at %#x (%s): %w", c.rip, inst, err)
	}
	c.rip = next
	return effect, nil
}
