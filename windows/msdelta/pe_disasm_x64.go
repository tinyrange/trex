package msdelta

type deltaX64Instruction struct {
	length int
	field  int
	remap  bool
}

// These operand-class tables describe the small length decoder used by the
// MSDelta AMD64 PE transform. They are deliberately independent of the normal
// x86 disassembler: malformed and truncated encodings have transform-specific
// advancement rules that affect every following instruction boundary.
var deltaX64ModRM1 = []byte{
	2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1,
	2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 2, 1, 1, 1, 1, 0, 2, 0, 2, 0, 0, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1,
	3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	2, 2, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 0, 0, 1, 0, 2, 2, 2, 2, 1, 1, 1, 0, 2, 2, 2, 2, 2, 2, 2, 2,
	4, 4, 4, 4, 0, 0, 0, 0, 5, 5, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 2, 2,
}

var deltaX64ModRM0F = []byte{
	2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 1, 0, 1, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 1, 1, 1, 1, 1, 1, 2, 2,
	5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	0, 0, 0, 2, 2, 2, 1, 1, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1,
}

var deltaX64Immediate1 = []byte{
	0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0,
	0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 5, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 4, 4, 4, 4, 4, 4, 4, 4,
	1, 1, 2, 0, 0, 0, 1, 5, 3, 0, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0,
}

var deltaX64Immediate0F = []byte{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
	0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

func decodeDeltaX64(code []byte) deltaX64Instruction {
	available := min(len(code), 15)
	if available == 0 {
		return deltaX64Instruction{}
	}
	stop := func(position int) deltaX64Instruction { return deltaX64Instruction{length: position, field: -1} }
	position := 0
	operand16, address32 := false, false
	for position < available {
		switch code[position] {
		case 0x66:
			operand16 = true
		case 0x67:
			address32 = true
		case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0xf0, 0xf2, 0xf3:
		default:
			goto prefixesDone
		}
		position++
	}
prefixesDone:
	if position >= available {
		return stop(position)
	}
	rexW := false
	if code[position]&0xf0 == 0x40 {
		rexW = code[position]&8 != 0
		position++
		if position >= available || code[position]&0xf0 == 0x40 {
			return stop(position)
		}
	}
	var modRMKind, immediateKind byte
	if code[position] == 0x0f {
		position++
		if position >= available {
			return stop(position)
		}
		opcode := code[position]
		modRMKind, immediateKind = deltaX64ModRM0F[opcode], deltaX64Immediate0F[opcode]
	} else {
		opcode := code[position]
		modRMKind, immediateKind = deltaX64ModRM1[opcode], deltaX64Immediate1[opcode]
	}
	position++
	if modRMKind == 1 {
		return stop(position)
	}
	field, remap, groupImmediate := -1, false, false
	switch modRMKind {
	case 2:
		if position >= available {
			return stop(position)
		}
		modRM := code[position]
		position++
		mode, rm := modRM>>6, modRM&7
		register := (modRM >> 3) & 7
		groupImmediate = register == 0 || register == 1
		if mode == 3 {
		} else if rm == 5 && mode == 0 {
			if available-position < 4 {
				return stop(position)
			}
			field, remap = position, true
			position += 4
		} else if rm == 4 {
			if position >= available {
				return stop(position)
			}
			sib := code[position]
			position++
			if mode == 0 && sib&7 == 5 {
				if available-position < 4 {
					return stop(position)
				}
				position += 4
			} else if mode == 1 {
				if position >= available {
					return stop(position)
				}
				position++
			} else if mode == 2 {
				if available-position < 4 {
					return stop(position)
				}
				position += 4
			}
		} else if mode == 1 {
			if position >= available {
				return stop(position)
			}
			position++
		} else if mode == 2 {
			if available-position < 4 {
				return stop(position)
			}
			position += 4
		}
	case 3:
		length := 8
		if address32 {
			length = 4
		}
		if available-position < length {
			return stop(position)
		}
		position += length
	case 4:
		if position >= available {
			return stop(position)
		}
		position++
	case 5:
		if available-position < 4 {
			return stop(position)
		}
		field, remap = position, true
		position += 4
	}
	switch immediateKind {
	case 1:
		if position >= available {
			return stop(position)
		}
		position++
	case 2:
		// RET/RETF imm16 use a fixed-width two-byte immediate in every mode.
		if available-position < 2 {
			return stop(position)
		}
		position += 2
	case 5:
		length := 4
		if operand16 && !rexW {
			length = 2
		}
		if available-position < length {
			return stop(position)
		}
		position += length
	case 3:
		// ENTER carries an imm16 allocation size followed by an imm8 nesting
		// level. The native transform treats the three trailing bytes as one
		// immediate class. Confusing this with the separately classified moffs
		// operand shifts every subsequent instruction boundary in the function.
		if available-position < 3 {
			return stop(position)
		}
		position += 3
	case 4:
		length := 4
		if rexW {
			length = 8
		} else if operand16 {
			length = 2
		}
		if available-position < length {
			return stop(position)
		}
		position += length
	case 6:
		if groupImmediate {
			if position >= available {
				return stop(position)
			}
			position++
		}
	case 7:
		if groupImmediate {
			length := 4
			if operand16 && !rexW {
				length = 2
			}
			if available-position < length {
				return stop(position)
			}
			position += length
		}
	}
	return deltaX64Instruction{length: position, field: field, remap: remap}
}
