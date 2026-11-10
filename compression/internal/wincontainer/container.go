// Package wincontainer reads bounded Windows Compression API frames.
package wincontainer

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

const (
	// CompressionAPIMagic identifies the chunked representation emitted by
	// the Windows Compression API.
	CompressionAPIMagic = uint32(0xc0e5510a)

	compressionAPIHeaderSize = 24
	maximumContainerChunk    = 64 << 20
)

// Decode expands a Windows Compression API container with the selected codec in
// memory. The declared total is checked against maximumOutputSize before any
// output allocation or chunk decompression occurs.
func Decode(data []byte, maximumOutputSize uint64, algorithm byte, decompress func([]byte, int) ([]byte, error)) ([]byte, error) {
	return DecodeInto(data, maximumOutputSize, algorithm, func(chunk, destination []byte) error {
		decoded, err := decompress(chunk, len(destination))
		if err != nil {
			return err
		}
		if len(decoded) != len(destination) {
			return fmt.Errorf("wincontainer: decoded chunk length %d, want %d", len(decoded), len(destination))
		}
		copy(destination, decoded)
		return nil
	})
}

// DecodeInto gives the codec an exact, capacity-clamped slice of the final
// output for each independent compressed chunk. The codec must fill it or
// return an error; it must not retain input or destination slices. The frame
// owns the allocation, and no partial result escapes on malformed input.
func DecodeInto(data []byte, maximumOutputSize uint64, algorithm byte, decompress func([]byte, []byte) error) ([]byte, error) {
	if len(data) < compressionAPIHeaderSize {
		return nil, fmt.Errorf("wincontainer: container has %d bytes, need at least %d", len(data), compressionAPIHeaderSize)
	}
	if magic := binary.LittleEndian.Uint32(data[0:4]); magic != CompressionAPIMagic {
		return nil, fmt.Errorf("wincontainer: invalid container magic %#x", magic)
	}
	headerSize := int(binary.LittleEndian.Uint16(data[4:6]))
	if headerSize < compressionAPIHeaderSize || headerSize > len(data) {
		return nil, fmt.Errorf("wincontainer: invalid container header size %d", headerSize)
	}
	if actual, expected := containerHeaderCRC(data[:headerSize]), data[6]; actual != expected {
		return nil, fmt.Errorf("wincontainer: container header CRC %#x does not match %#x", actual, expected)
	}
	if data[7] != algorithm {
		return nil, fmt.Errorf("wincontainer: unsupported container algorithm %d", data[7])
	}
	total := binary.LittleEndian.Uint64(data[8:16])
	if total > maximumOutputSize {
		return nil, fmt.Errorf("wincontainer: container output size %d exceeds limit %d", total, maximumOutputSize)
	}
	if total > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("wincontainer: container output size %d is too large", total)
	}
	chunkSize := binary.LittleEndian.Uint32(data[16:20])
	if chunkSize == 0 || chunkSize > maximumContainerChunk {
		return nil, fmt.Errorf("wincontainer: invalid container chunk size %d", chunkSize)
	}
	if flags := binary.LittleEndian.Uint32(data[20:24]); flags != 0 {
		return nil, fmt.Errorf("wincontainer: unsupported container flags %#x", flags)
	}

	output := make([]byte, int(total))
	position := 0
	offset := headerSize
	for uint64(position) < total {
		if len(data)-offset < 4 {
			return nil, fmt.Errorf("wincontainer: truncated container chunk header at %#x", offset)
		}
		compressedSize := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
		remaining := total - uint64(position)
		uncompressedSize := min(uint64(chunkSize), remaining)
		if compressedSize == 0 || uint64(compressedSize) > uncompressedSize {
			return nil, fmt.Errorf("wincontainer: invalid compressed chunk size %d for %d output bytes", compressedSize, uncompressedSize)
		}
		if uint64(compressedSize) > uint64(len(data)-offset) {
			return nil, fmt.Errorf("wincontainer: truncated container chunk at %#x", offset)
		}
		chunk := data[offset : offset+int(compressedSize)]
		offset += int(compressedSize)
		end := position + int(uncompressedSize)
		destination := output[position:end:end]
		if uint64(compressedSize) == uncompressedSize {
			copy(destination, chunk)
		} else if err := decompress(chunk, destination); err != nil {
			return nil, fmt.Errorf("wincontainer: container chunk at output offset %#x: %w", position, err)
		}
		position = end
	}
	if offset != len(data) {
		return nil, fmt.Errorf("wincontainer: container has %d trailing bytes", len(data)-offset)
	}
	return output, nil
}

func containerHeaderCRC(header []byte) byte {
	checksum := crc32.NewIEEE()
	_, _ = checksum.Write(header[:6])
	_, _ = checksum.Write(header[7:])
	return byte(checksum.Sum32())
}
