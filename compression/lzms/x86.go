package lzms

import "encoding/binary"

func restoreX86Addresses(data []byte) {
	const unseen = -1 << 30
	closestLikelyCode := unseen
	lastTargetUsage := make([]int, 1<<16)
	for index := range lastTargetUsage {
		lastTargetUsage[index] = unseen
	}
	for position := 1; position < len(data)-16; {
		// Most bytes (especially data/zero regions in a solid ESD chunk) are
		// not instruction prefixes handled by this transform. Reject eight
		// bytes at once using a conservative opcode filter. False positives
		// take the ordinary scalar path; no candidate can be skipped.
		if position+8 <= len(data)-16 {
			word := binary.LittleEndian.Uint64(data[position : position+8])
			a := (word & 0x5858585858585858) ^ 0x4848484848484848
			b := (word & 0xf0f0f0f0f0f0f0f0) ^ 0xf0f0f0f0f0f0f0f0
			const ones = uint64(0x0101010101010101)
			const highs = uint64(0x8080808080808080)
			if ((a-ones)&^a|(b-ones)&^b)&highs == 0 {
				position += 8
				continue
			}
		}
		// E9 is scan-only: consume its operand but do not let it participate in
		// translation or target-recency state.
		switch data[position] {
		case 0xe9:
			position += 5
			continue
		case 0x48, 0x4c, 0xe8, 0xf0, 0xff:
			// Only these leading bytes can be a candidate. Most payload bytes
			// are not instructions; avoid the non-inline recognizer for them.
		default:
			position++
			continue
		}
		operandOffset, window, recognized := x86Candidate(data, position)
		if !recognized {
			position++
			continue
		}
		operand := position + operandOffset
		value := binary.LittleEndian.Uint32(data[operand : operand+4])
		operandEnd := operand + 3
		if position-closestLikelyCode <= window {
			value -= uint32(position)
			binary.LittleEndian.PutUint32(data[operand:operand+4], value)
		}
		key := uint16(uint32(position) + uint32(uint16(value)))
		if operandEnd-lastTargetUsage[key] <= 65535 {
			closestLikelyCode = operandEnd
		}
		lastTargetUsage[key] = operandEnd
		position = operandEnd + 1
	}
}

func x86Candidate(data []byte, position int) (operandOffset, window int, recognized bool) {
	switch data[position] {
	case 0x48:
		if data[position+1] == 0x8b && (data[position+2] == 0x05 || data[position+2] == 0x0d) {
			return 3, 1023, true
		}
		if data[position+1] == 0x8d && data[position+2]&7 == 5 {
			return 3, 1023, true
		}
	case 0x4c:
		if data[position+1] == 0x8d && data[position+2]&7 == 5 {
			return 3, 1023, true
		}
	case 0xe8:
		return 1, 511, true
	case 0xe9:
		return 1, 0, true
	case 0xf0:
		if data[position+1] == 0x83 && data[position+2] == 0x05 {
			return 3, 1023, true
		}
	case 0xff:
		if data[position+1] == 0x15 {
			return 2, 1023, true
		}
	}
	return 0, 0, false
}
