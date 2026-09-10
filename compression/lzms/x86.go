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
		// E9 is scan-only: consume its operand but do not let it participate in
		// translation or target-recency state.
		if data[position] == 0xe9 {
			position += 5
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
