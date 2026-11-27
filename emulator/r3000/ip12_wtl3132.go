package r3000

import "math"

// ip12WTL3132 models the GE5 arithmetic coprocessor's four-stage
// pipeline. Operands are captured from the register file when an
// instruction enters the pipeline.
type ip12WTL3132 struct {
	regs      [32]uint32
	temp      [3]uint32
	pipe      [3]wtlInstruction
	mode      uint16
	input     uint32
	output    uint32
	condition bool
	overflow  bool
}

type wtlInstruction struct {
	code      uint64
	a, b      uint32
	x         uint32
	product   uint32
	result    uint32
	condition bool
	valid     bool
	cancel    bool
}

func (f *ip12WTL3132) step(code uint64, neutralize bool) {
	retire, alu, mult := f.pipe[2], f.pipe[1], f.pipe[0]

	var forward bool
	c := (retire.code >> 16) & 31
	if retire.valid && !retire.cancel {
		if dest := (retire.code >> 3) & 3; dest != 3 {
			f.temp[dest] = retire.result
		}
		f.condition = retire.condition
		forward = retire.code&(1<<15) == 0
	}
	if alu.valid && !alu.cancel {
		f.calculate(&alu)
	}
	if mult.valid {
		if (mult.code>>13)&3 == 2 {
			f.output = mult.x
		}
		f.multiply(&mult)
		mult.cancel = neutralize
	}

	aID, bID, dID := (code>>26)&31, (code>>21)&31, (code>>8)&31
	in := wtlInstruction{code: code, a: f.regs[aID], b: f.regs[bID], x: f.input, valid: true}
	if forward {
		if f.mode&1 != 0 && aID == c {
			in.a = retire.result
		}
		if f.mode&0x800 != 0 && bID == c {
			in.b = retire.result
		}
	}
	switch (code >> 13) & 3 {
	case 1, 3:
		f.regs[dID] = f.input
		if f.mode&8 != 0 && aID == dID {
			in.a = f.input
		}
	case 2:
		in.x = f.regs[dID]
		if forward && f.mode&0x10 != 0 && dID == c {
			in.x = retire.result
		}
	}
	if code>>31 == 0 {
		switch bID {
		case 0:
			f.overflow = false
		case 1:
			f.output = truth(f.overflow)
		case 3:
			f.mode = uint16((code>>5)&7)<<10 | uint16((code>>16)&31)<<5 | uint16(aID)
			if f.mode&0x20 == 0 {
				f.overflow = false
			}
		}
	}
	if forward {
		f.regs[c] = retire.result
	}
	f.pipe = [3]wtlInstruction{in, mult, alu}
}

func (f *ip12WTL3132) multiply(i *wtlInstruction) {
	function := i.code >> 31
	if function >= 5 {
		b := i.b
		if i.code&4 != 0 {
			b = i.x
		}
		product := math.Float32frombits(i.a) * math.Float32frombits(b)
		if function != 7 {
			product = -product
		}
		i.product = math.Float32bits(product)
	}
	switch (i.code >> 5) & 7 {
	case 0:
		i.b = i.x
	case 2:
		i.b = f.temp[1]
	case 3:
		i.b = f.temp[2]
	case 4:
		i.b = f.temp[0]
	case 6:
		i.b = math.Float32bits(2)
	case 7:
		i.b = 0
	}
}

func (f *ip12WTL3132) calculate(i *wtlInstruction) {
	a, b := math.Float32frombits(i.a), math.Float32frombits(i.b)
	i.condition = f.condition
	var result float32
	switch i.code >> 31 {
	case 0:
		switch (i.code >> 21) & 31 {
		case 4:
			result = math.Float32frombits(i.a & 0x7fffffff)
		case 5:
			result = float32(int32(i.a))
		case 6:
			x := math.Floor(float64(a))
			if f.mode&2 != 0 {
				x = math.RoundToEven(float64(a))
			}
			i.result = uint32(int32(int32(x)<<8) >> 8)
			return
		case 7:
			result = 1 / a
		default:
			return
		}
	case 1:
		result = b - a
	case 2:
		result = a - b
	case 3:
		result = a + b
	case 5, 7:
		result = math.Float32frombits(i.product) + b
	case 6:
		result = math.Float32frombits(i.product) - b
	}
	i.result = math.Float32bits(result)
	switch i.code & 3 {
	case 1:
		i.condition = result <= 0
	case 2:
		i.condition = result < 0
	case 3:
		i.condition = result == 0
	}
	if math.IsInf(float64(result), 0) && !math.IsInf(float64(a), 0) && !math.IsInf(float64(b), 0) {
		f.overflow = true
	}
}
