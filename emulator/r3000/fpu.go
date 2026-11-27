package r3000

import "math"

func (c *cpu) cop1(word uint32, format, ft, fs uint8, x *instruction) {
	if c.cp0[status]&(1<<29) == 0 {
		x.exception, x.coprocessor = 11, 1
		return
	}
	switch format {
	case 0:
		x.load = delayedLoad{ft, c.fpr[fs]}
	case 2:
		x.load.reg = ft
		switch fs {
		case 0:
			x.load.value = c.fpuRevision
		case 31:
			x.load.value = c.fcsr
		}
	case 4:
		x.fpLoad = delayedLoad{fs, c.gpr[ft]}
	case 6:
		if fs == 31 {
			c.fcsr = c.gpr[ft]
		}
	case 8:
		if ft > 1 {
			x.exception = 10
			return
		}
		x.jump((c.fcsr&(1<<23) != 0) == (ft == 1), c.pc, uint32(int32(int16(word)))<<2)
	case 16, 17, 20:
		c.floatOperation(word, format, ft, fs, x)
	default:
		x.exception = 10
	}
}

func (c *cpu) floatOperation(word uint32, format, ft, fs uint8, x *instruction) {
	fd, function := uint8(word>>6&31), word&63
	double := format == 17
	if double && (fs&1 != 0 || ((function <= 3 || function >= 48) && ft&1 != 0)) {
		x.exception = 10
		return
	}
	// R3010 register pairs always put the low word in the even register.
	// Endianness only changes the order of those words in memory.
	read := func(reg uint8) float64 {
		switch format {
		case 17:
			return math.Float64frombits(uint64(c.fpr[reg]) | uint64(c.fpr[reg+1])<<32)
		case 20:
			return float64(int32(c.fpr[reg]))
		default:
			return float64(math.Float32frombits(c.fpr[reg]))
		}
	}
	if format == 20 && function != 32 && function != 33 {
		x.exception = 10
		return
	}
	value, flags := read(fs), uint32(0)
	switch function {
	case 0:
		value += read(ft)
	case 1:
		value -= read(ft)
	case 2:
		value *= read(ft)
	case 3:
		divisor := read(ft)
		if divisor == 0 && !math.IsNaN(value) && !math.IsInf(value, 0) {
			if value == 0 {
				flags |= 16
			} else {
				flags |= 8
			}
		}
		value /= divisor
	case 5:
		value = math.Abs(value)
	case 6:
	case 7:
		value = -value
	case 32:
		double = false
	case 33:
		double = true
	case 36:
		rounded := value
		switch c.fcsr & 3 {
		case 0:
			rounded = math.RoundToEven(value)
		case 1:
			rounded = math.Trunc(value)
		case 2:
			rounded = math.Ceil(value)
		case 3:
			rounded = math.Floor(value)
		}
		bits := uint32(0x80000000)
		if math.IsNaN(rounded) || rounded < math.MinInt32 || rounded > math.MaxInt32 {
			flags |= 16
		} else {
			bits = uint32(int32(rounded))
			if rounded != value {
				flags |= 1
			}
		}
		if c.floatFlags(flags) {
			x.fpWrite = delayedLoad{fd, bits}
		}
		return
	default:
		if function < 48 {
			x.exception = 10
			return
		}
		other := read(ft)
		unordered := math.IsNaN(value) || math.IsNaN(other)
		if unordered && function&8 != 0 {
			flags |= 16
		}
		if c.floatFlags(flags) {
			c.fcsr &^= 1 << 23
			if (unordered && function&1 != 0) || (value == other && function&2 != 0) || (value < other && function&4 != 0) {
				c.fcsr |= 1 << 23
			}
		}
		return
	}
	if double && fd&1 != 0 {
		x.exception = 10
		return
	}
	bits := math.Float64bits(value)
	if !double {
		rounded := float32(value)
		if float64(rounded) != value && !math.IsNaN(value) {
			flags |= 1
			if math.IsInf(float64(rounded), 0) {
				flags |= 4
			}
			if math.Abs(value) < 0x1p-126 {
				flags |= 2
			}
		}
		bits = uint64(math.Float32bits(rounded))
	}
	if c.floatFlags(flags) {
		x.fpWrite = delayedLoad{fd, uint32(bits)}
		if double {
			x.fpHigh = delayedLoad{fd + 1, uint32(bits >> 32)}
		}
	}
}

func (c *cpu) floatFlags(flags uint32) bool {
	c.fcsr = (c.fcsr &^ (0x3f << 12)) | flags<<12
	enabled := c.fcsr >> 7 & 31
	c.fcsr |= (flags &^ enabled) << 2
	return flags&enabled == 0
}
