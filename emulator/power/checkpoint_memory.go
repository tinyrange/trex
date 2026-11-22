package power

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/klauspost/compress/s2"
)

// Keep the working buffer independent of partition size. A nil block
// represents zeros, including when a previously clean block is later written.
const checkpointBlockSize = 64 << 10

var checkpointZeros [checkpointBlockSize]byte

type checkpointMemory struct {
	size   int
	blocks [][]byte
}

func captureMemory(mem []byte) checkpointMemory {
	c := checkpointMemory{size: len(mem)}
	var scratch []byte
	for block := range slices.Chunk(mem, checkpointBlockSize) {
		var saved []byte
		if !bytes.Equal(block, checkpointZeros[:len(block)]) {
			scratch = s2.Encode(scratch, block)
			saved = bytes.Clone(scratch)
		}
		c.blocks = append(c.blocks, saved)
	}
	return c
}

func (c checkpointMemory) restore(dst []byte) error {
	for i, encoded := range c.blocks {
		start := i * checkpointBlockSize
		end := min(start+checkpointBlockSize, len(dst))
		block := dst[start:end:end]
		if encoded == nil {
			if !bytes.Equal(block, checkpointZeros[:len(block)]) {
				clear(block)
			}
			continue
		}
		decoded, err := s2.Decode(block, encoded)
		if err != nil || len(decoded) != len(block) {
			return fmt.Errorf("power: invalid checkpoint memory block %d", i)
		}
	}
	return nil
}
