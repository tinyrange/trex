package vmsbackup

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

const blockHeaderSize = 256

// headerChecksum computes the BACKUP header CRC independently of the block
// CRC. Both stored checksum fields participate as zero bytes. The reflected
// CRC-16 polynomial is 0xa001, with initial value zero and no final XOR.
func headerChecksum(header []byte) uint16 {
	var crc uint16
	for i, b := range header {
		if i >= 36 && i < 40 || i >= 254 {
			b = 0
		}
		crc ^= uint16(b)
		for bit := 0; bit < 8; bit++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xa001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// ValidateHeaderChecksum validates a 256-byte BACKUP block header. It neither
// validates the payload CRC nor interprets the header's structural fields.
func ValidateHeaderChecksum(header []byte) error {
	if len(header) != blockHeaderSize {
		return fmt.Errorf("vms backup: header must contain %d bytes", blockHeaderSize)
	}
	want := binary.LittleEndian.Uint16(header[254:])
	if got := headerChecksum(header); got != want {
		return fmt.Errorf("vms backup: header checksum: got %04x, want %04x", got, want)
	}
	return nil
}

// ValidateBlockChecksums validates both checksums of a complete BACKUP block.
// The caller is responsible for determining the block length from framing.
// Data and XOR redundancy blocks use the same checksum rules.
func ValidateBlockChecksums(block []byte) error {
	if len(block) < blockHeaderSize {
		return fmt.Errorf("vms backup: truncated block header")
	}
	if err := ValidateHeaderChecksum(block[:blockHeaderSize]); err != nil {
		return err
	}
	want := binary.LittleEndian.Uint32(block[36:])
	if got := blockChecksum(block); got != want {
		return fmt.Errorf("vms backup: block checksum: got %08x, want %08x", got, want)
	}
	return nil
}

func blockChecksum(block []byte) uint32 {
	var zero [4]byte
	crc := crc32.ChecksumIEEE(block[:36])
	crc = crc32.Update(crc, crc32.IEEETable, zero[:])
	crc = crc32.Update(crc, crc32.IEEETable, block[40:254])
	crc = crc32.Update(crc, crc32.IEEETable, zero[:2])
	return crc32.Update(crc, crc32.IEEETable, block[256:])
}
