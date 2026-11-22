package power

// Decimal carries are binary carries at nibble boundaries, not BCD arithmetic.
// PowerPC AS Book I pp34-35,61: only addc/subfc set DC and its summary DS.
func (c *CPU) decimalCarries(a, b, result uint64) {
	if !c.m.as || c.MSR&MSRTA == 0 {
		return
	}
	carries := a&b | (a|b)&^result
	var dc uint64
	for digit := uint(0); digit < 16; digit++ {
		dc |= (carries >> (4*digit + 3) & 1) << digit
	}
	c.XER = c.XER&^(uint64(0xffff)<<32|uint64(1)<<23) | dc<<32
	if dc != 0 {
		c.XER |= 1 << 23
	}
}

// OC chooses the offset boundary from the original first operand, before
// writing a possibly aliased destination. Unlike DC it also applies to addic.
func (c *CPU) offsetCarry(a, b, result uint64) {
	if !c.m.as || c.MSR&MSRTA == 0 {
		return
	}
	bit := uint(47) // architectural bit16
	if a>>48 != 0 {
		bit = 23 // architectural bit40
	}
	carries := a&b | (a|b)&^result
	c.XER = c.XER&^(uint64(1)<<28) | (carries>>bit&1)<<28
}

func (c *CPU) decimalSixes() uint64 {
	dc := c.XER >> 32
	var result uint64
	for digit := uint(0); digit < 16; digit++ {
		if dc>>digit&1 == 0 {
			result |= uint64(6) << (4 * digit)
		}
	}
	return result
}
