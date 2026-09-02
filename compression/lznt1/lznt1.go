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
		want := min(chunkSize, remaining)
		if header&0x8000 == 0 {
			if len(encoded) < want {
				return nil, fmt.Errorf("lznt1: short uncompressed chunk: %d bytes, expected %d", len(encoded), want)
			}
			output = append(output, encoded[:want]...)
			continue
		}
		chunk, err := decodeChunk(encoded, want)
		if err != nil {
			return nil, err
		}
		output = append(output, chunk...)
	}
	return output, nil
}

func decodeChunk(input []byte, expected int) ([]byte, error) {
	output := make([]byte, 0, expected)
	for offset := 0; offset < len(input) && len(output) < expected; {
		flags := input[offset]
		offset++
		for bit := uint(0); bit < 8 && len(output) < expected; bit++ {
			if flags&(1<<bit) == 0 {
				if offset >= len(input) {
					return nil, fmt.Errorf("lznt1: truncated literal")
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
			for count := 0; count < length && len(output) < expected; count++ {
				output = append(output, output[len(output)-displacement])
			}
		}
	}
	if len(output) != expected {
		return nil, fmt.Errorf("lznt1: chunk produced %d bytes, expected %d", len(output), expected)
	}
	return output, nil
}
