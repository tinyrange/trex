package adcr

import (
	"encoding/binary"
	"fmt"
)

// decodeVersion1 follows the bounded DCMP128 implementation in the AOL2.7
// installer. It maintains sixteen buckets of 256 phrase pointers, using a
// shared rolling insertion counter. No loader code or built-in seed is used.
func decodeVersion1(input, seed []byte, target int) ([]byte, error) {
	if len(input) < 8 || input[0] != 0 || input[1] != 0 || input[2] != 0 || input[3] != 0 || uint64(binary.BigEndian.Uint32(input[4:])) != uint64(len(input)-8) {
		return nil, fmt.Errorf("adcr1: invalid stored framing")
	}
	return decodeVersion1Stream(input[8:], seed, target)
}

func decodeVersion1Stream(input, seed []byte, target int) ([]byte, error) {
	table := [4096]int{}
	for i := range table {
		table[i] = -1
	}
	out := make([]byte, 0, target)
	counter, pending, control := 0, 0, uint32(1)
	insert := func(at int) {
		index := ((int(out[at])+int(out[at+1])+int(out[at+2]))&30)*128 + counter
		table[index] = at
		counter = (counter + 1) & 255
	}
	for pos := 0; pos < len(input); {
		if control == 1 {
			if len(input)-pos < 2 {
				return nil, fmt.Errorf("adcr1: truncated control word")
			}
			control = 0x10000 | uint32(binary.LittleEndian.Uint16(input[pos:]))
			pos += 2
		}
		match := control&1 != 0
		control >>= 1
		if match {
			if len(input)-pos < 2 {
				return nil, fmt.Errorf("adcr1: truncated match")
			}
			index := int(input[pos]&240)<<4 | int(input[pos+1])
			count := int(input[pos]&15) + 3
			pos += 2
			if count > target-len(out) {
				return nil, fmt.Errorf("adcr1: match exceeds decoded size")
			}
			start, source := len(out), table[index]
			if source == -1 {
				if count > len(seed) {
					return nil, fmt.Errorf("adcr1: match requires explicit seed bytes")
				}
				out = append(out, seed[:count]...)
			} else {
				for i := 0; i < count; i++ {
					out = append(out, out[source+i])
				}
			}
			for at := start - pending; at < start; at++ {
				insert(at)
			}
			pending = 0
			table[(index&3840)+counter] = start
			counter = (counter + 1) & 255
		} else {
			if pos == len(input) || len(out) == target {
				return nil, fmt.Errorf("adcr1: literal outside input or decoded size")
			}
			out = append(out, input[pos])
			pos++
			pending++
			if pending == 3 {
				insert(len(out) - 3)
				pending = 2
			}
		}
	}
	if len(out) != target {
		return nil, fmt.Errorf("adcr1: decoded size mismatch")
	}
	return out, nil
}
