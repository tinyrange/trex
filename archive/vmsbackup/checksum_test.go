package vmsbackup

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestHeaderChecksum(t *testing.T) {
	header := make([]byte, blockHeaderSize)
	for i := range header {
		header[i] = byte(i)
	}
	// Independently calculated by the bitwise Starlark REPL probe for this
	// constructed byte ramp, not obtained from the implementation under test.
	binary.LittleEndian.PutUint16(header[254:], 60997)
	original := bytes.Clone(header)
	if err := ValidateHeaderChecksum(header); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(header, original) {
		t.Fatal("validation mutated its input")
	}
	for i := range header {
		changed := bytes.Clone(header)
		changed[i] ^= 1
		err := ValidateHeaderChecksum(changed)
		if i >= 36 && i < 40 {
			if err != nil {
				t.Fatalf("block CRC byte %d affected header CRC: %v", i, err)
			}
		} else if err == nil {
			t.Fatalf("accepted corruption at byte %d", i)
		}
	}
	for _, size := range []int{0, 36, 254, 255, 257, 512} {
		if err := ValidateHeaderChecksum(make([]byte, size)); err == nil {
			t.Fatalf("accepted size %d", size)
		}
	}
}

func TestBlockChecksums(t *testing.T) {
	block := make([]byte, 2048)
	for i := range block {
		block[i] = byte(i)
	}
	// Independent Starlark bitwise CRC results for a constructed byte ramp.
	binary.LittleEndian.PutUint16(block[254:], 60997)
	binary.LittleEndian.PutUint32(block[36:], 2364072670)
	original := bytes.Clone(block)
	if err := ValidateBlockChecksums(block); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(block, original) {
		t.Fatal("validation mutated block")
	}
	for i := range block {
		changed := bytes.Clone(block)
		changed[i] ^= 1
		if err := ValidateBlockChecksums(changed); err == nil {
			t.Fatalf("accepted corruption at byte %d", i)
		}
	}
	for _, size := range []int{0, 36, 254, 255, 256, 2047} {
		if err := ValidateBlockChecksums(block[:size]); err == nil {
			t.Fatalf("accepted truncation to %d", size)
		}
	}
	if err := ValidateBlockChecksums(append(bytes.Clone(block), 0)); err == nil {
		t.Fatal("accepted extra byte")
	}
}
