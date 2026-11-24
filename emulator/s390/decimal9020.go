package s390

// The Model 65 stores partial decimal results before reporting some data
// exceptions. See 2065 Processing Unit FEMI, 226-2037-0, §§3.8.1 and 3.8.3.

// addInvalid9020 handles an invalid digit in AP or SP. The serial adder
// forces its entire sum byte to ones when either input digit is invalid.
// The marked result bytes reach main storage before the data interruption.
func (c *CPU) addInvalid9020(a1 uint32, b1 int, l1 uint32, a2 uint32, b2 int, l2 uint32, subtract bool) {
	last1 := c.fetchByte(a1+l1-1, b1)
	last2 := c.fetchByte(a2+l2-1, b2)
	if last1&0xf < 0xa || last2&0xf < 0xa {
		return
	}
	neg := packedNegative(last1)
	subtractMagnitude := (neg != packedNegative(last2)) != subtract
	carry := 0
	if subtractMagnitude {
		carry = 1
	}
	var result [16]byte
	for i := uint32(0); i < l1; i++ {
		x := c.fetchByte(a1+l1-1-i, b1)
		var y byte
		if i < l2 {
			y = c.fetchByte(a2+l2-1-i, b2)
		}
		lo := c.decimalSign(neg)
		invalid := x>>4 > 9 || y>>4 > 9
		if i != 0 {
			invalid = invalid || x&0xf > 9 || y&0xf > 9
			lo, carry = serialDecimalDigit(x&0xf, y&0xf, carry, subtractMagnitude)
		}
		var hi byte
		hi, carry = serialDecimalDigit(x>>4, y>>4, carry, subtractMagnitude)
		result[i] = hi<<4 | lo
		if invalid {
			result[i] = 0xff
		}
	}
	if subtractMagnitude && carry == 0 && l2 <= l1 {
		// The subtraction left a ten's complement magnitude. Re-complement
		// it, including the carry through any invalid adder byte.
		carry = 1
		for i, x := range result[:l1] {
			lo := c.decimalSign(!neg)
			if i != 0 {
				lo, carry = serialDecimalDigit(0, x&0xf, carry, true)
			}
			var hi byte
			hi, carry = serialDecimalDigit(0, x>>4, carry, true)
			if x != 0xff {
				result[i] = hi<<4 | lo
			}
		}
	}
	for i, x := range result[:l1] {
		c.storeByte(a1+l1-1-uint32(i), b1, x)
	}
}

// serialDecimalDigit uses the carry from the binary adder, before decimal
// correction. Addition supplies excess six, subtraction a complemented digit.
func serialDecimalDigit(x, y byte, carry int, subtract bool) (byte, int) {
	source := int(y) + 6
	if subtract {
		source = 15 - int(y)
	}
	sum := int(x) + source + carry
	if sum >= 16 {
		return byte(sum & 15), 1
	}
	return byte(sum-6) & 15, 0
}

func (c *CPU) multiply9020(a1 uint32, b1 int, l1 uint32, a2 uint32, b2 int, l2 uint32) {
	x := c.packed(a1+l2, b1, l1-l2)
	y := c.packed(a2, b2, l2)
	neg := packedNegative(c.fetchByte(a1+l1-1, b1)) != packedNegative(c.fetchByte(a2+l2-1, b2))
	x.Mul(x, y)
	result, _ := packedBytes(l1, x, c.decimalSign(neg))
	// The effective multiplicand excludes the leading workspace bytes.
	// The low product is written first, then the rest replaces the
	// workspace from right to left through the first nonzero byte.
	for i := l1; i > 0; {
		i--
		nonzero := i < l2 && c.fetchByte(a1+i, b1) != 0
		c.storeByte(a1+i, b1, result[i])
		if nonzero {
			c.program(pgmData)
		}
	}
}
