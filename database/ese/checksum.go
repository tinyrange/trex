package ese

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

const pageFlagNewChecksum = 0x00002000

// oldChecksum computes the original ESE XOR checksum. The checksum word at
// offset zero is excluded from the calculation.
func oldChecksum(data []byte) (uint32, error) {
	if len(data) == 0 || len(data)%4 != 0 {
		return 0, fmt.Errorf("ese: checksum input size %d is not DWORD aligned", len(data))
	}
	checksum := uint32(0x89abcdef)
	for offset := 4; offset < len(data); offset += 4 {
		checksum ^= binary.LittleEndian.Uint32(data[offset : offset+4])
	}
	return checksum, nil
}

// newBlockChecksum computes ESE's XOR/ECC checksum directly from the Hsiao
// code definition. The first eight bytes of a header block contain stored
// checksums and are treated as zero.
func newBlockChecksum(data []byte, pageNumber uint32, header bool) (uint64, error) {
	if len(data) < 1024 || len(data) > 8192 || len(data)&(len(data)-1) != 0 {
		return 0, fmt.Errorf("ese: invalid checksum block size %d", len(data))
	}
	start := 0
	if header {
		start = 8
	}
	var xor, indexParity uint32
	setParity := 0
	for offset := start; offset < len(data); offset += 4 {
		value := binary.LittleEndian.Uint32(data[offset : offset+4])
		xor ^= value
		setParity ^= bits.OnesCount32(value) & 1
		for value != 0 {
			bit := bits.TrailingZeros32(value)
			indexParity ^= uint32(offset*8 + bit)
			value &= value - 1
		}
	}
	mask := uint32(len(data)*8 - 1)
	complementParity := indexParity
	if setParity != 0 {
		complementParity ^= mask
	}
	ecc := (complementParity << 16) | indexParity
	return uint64(ecc)<<32 | uint64(xor^pageNumber), nil
}

func pageChecksums(data []byte, pageNumber uint32) ([4]uint64, error) {
	var result [4]uint64
	if len(data) != 16384 && len(data) != 32768 {
		return result, fmt.Errorf("ese: extended checksums require 16 KiB or 32 KiB pages")
	}
	blockSize := 4096
	if len(data) == 32768 {
		blockSize = 8192
	}
	for index := range result {
		start := index * blockSize
		checksum, err := newBlockChecksum(data[start:start+blockSize], pageNumber, index == 0)
		if err != nil {
			return result, err
		}
		result[index] = checksum
	}
	return result, nil
}

func setPageChecksum(data []byte, pageNumber uint32) error {
	if len(data) < 40 {
		return fmt.Errorf("ese: short page")
	}
	flags := binary.LittleEndian.Uint32(data[36:40]) | pageFlagNewChecksum
	binary.LittleEndian.PutUint32(data[36:40], flags)
	if len(data) > 8192 {
		binary.LittleEndian.PutUint32(data[64:68], pageNumber)
		checksums, err := pageChecksums(data, pageNumber)
		if err != nil {
			return err
		}
		binary.LittleEndian.PutUint64(data[40:48], checksums[1])
		binary.LittleEndian.PutUint64(data[48:56], checksums[2])
		binary.LittleEndian.PutUint64(data[56:64], checksums[3])
		// The secondary checksums are covered by the header-block checksum.
		checksums, err = pageChecksums(data, pageNumber)
		if err != nil {
			return err
		}
		binary.LittleEndian.PutUint64(data[0:8], checksums[0])
		return nil
	}
	checksum, err := newBlockChecksum(data, pageNumber, true)
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(data[0:8], checksum)
	return nil
}

func verifyPageChecksum(data []byte, pageNumber uint32) error {
	if len(data) < 40 {
		return fmt.Errorf("ese: page %d is short", pageNumber)
	}
	if binary.LittleEndian.Uint32(data[36:40])&pageFlagNewChecksum == 0 {
		actual, err := oldChecksum(data)
		if err != nil {
			return err
		}
		if expected := binary.LittleEndian.Uint32(data[:4]); expected != actual {
			return fmt.Errorf("ese: page %d checksum %#x != %#x", pageNumber, actual, expected)
		}
		return nil
	}
	actual, err := pageChecksums(data, pageNumber)
	if err != nil {
		return err
	}
	expected := [4]uint64{
		binary.LittleEndian.Uint64(data[0:8]),
		binary.LittleEndian.Uint64(data[40:48]),
		binary.LittleEndian.Uint64(data[48:56]),
		binary.LittleEndian.Uint64(data[56:64]),
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return fmt.Errorf("ese: page %d checksum block %d %#x != %#x", pageNumber, index, actual[index], expected[index])
		}
	}
	return nil
}
