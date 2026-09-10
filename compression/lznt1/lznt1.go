// Package lznt1 decodes the chunked LZNT1 format used by NTFS compression.
package lznt1

import (
	"encoding/binary"
	"fmt"
)

const chunkSize = 4096

// Decode expands an LZNT1 stream to exactly expected bytes. Trailing zero
// padding after the requested output is ignored, as required for compressed
// NTFS allocation units.
func Decode(input []byte, expected int) ([]byte, error) {
	if expected < 0 {
		return nil, fmt.Errorf("lznt1: negative output size")
	}
	output := make([]byte, 0, expected)
	for offset := 0; len(output) < expected; {
		if offset+2 > len(input) {
			return nil, fmt.Errorf("lznt1: truncated chunk header at %#x", offset)
		}
		header := binary.LittleEndian.Uint16(input[offset : offset+2])
		offset += 2
		if header == 0 {
			return nil, fmt.Errorf("lznt1: zero padding before expected output (%d of %d bytes)", len(output), expected)
		}
		if header&0x7000 != 0x3000 {
			return nil, fmt.Errorf("lznt1: invalid chunk signature %#x", header)
		}
		encodedSize := int(header&0x0fff) + 1
		if offset+encodedSize > len(input) {
			return nil, fmt.Errorf("lznt1: truncated chunk payload at %#x", offset)
		}
		encoded := input[offset : offset+encodedSize]
		offset += encodedSize
		remaining := expected - len(output)
		if header&0x8000 == 0 {
			output = append(output, encoded[:min(len(encoded), remaining)]...)
			continue
		}
		chunk, err := decodeChunk(encoded, chunkSize)
		if err != nil {
			return nil, err
		}
		if len(chunk) == 0 {
			return nil, fmt.Errorf("lznt1: compressed chunk produced no output")
		}
		output = append(output, chunk[:min(len(chunk), remaining)]...)
	}
	return output, nil
}

func decodeChunk(input []byte, maximum int) ([]byte, error) {
	output := make([]byte, 0, maximum)
	for offset := 0; offset < len(input); {
		flags := input[offset]
		offset++
		for bit := uint(0); bit < 8; bit++ {
			// A final flag group may contain fewer than eight data items. Once
			// its chunk payload is exhausted, the unused flag bits are ignored.
			if offset == len(input) {
				break
			}
			if flags&(1<<bit) == 0 {
				if len(output) == maximum {
					return nil, fmt.Errorf("lznt1: chunk output exceeds %d bytes", maximum)
				}
				output = append(output, input[offset])
				offset++
				continue
			}
			if offset+2 > len(input) {
				return nil, fmt.Errorf("lznt1: truncated phrase token")
			}
			token := binary.LittleEndian.Uint16(input[offset : offset+2])
			offset += 2
			lengthMask := uint16(0x0fff)
			displacementShift := uint(12)
			// The split is selected from the zero-based position of the
			// next output byte. Using len(output) directly advances the
			// split one token too early at each power-of-two boundary.
			for position := len(output) - 1; position >= 0x10; position >>= 1 {
				lengthMask >>= 1
				displacementShift--
			}
			length := int(token&lengthMask) + 3
			displacement := int(token>>displacementShift) + 1
			if displacement > len(output) {
				return nil, fmt.Errorf("lznt1: phrase displacement %d exceeds chunk output %d", displacement, len(output))
			}
			if length > maximum-len(output) {
				return nil, fmt.Errorf("lznt1: phrase output exceeds %d bytes", maximum)
			}
			for count := 0; count < length; count++ {
				output = append(output, output[len(output)-displacement])
			}
		}
	}
	return output, nil
}
