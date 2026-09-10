package lzms

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

const (
	// CompressionAPIMagic identifies the chunked LZMS representation emitted by
	// the Windows Compression API.
	CompressionAPIMagic = uint32(0xc0e5510a)

	compressionAPIHeaderSize = 24
	compressionAPIAlgorithm  = 5
	maximumContainerChunk    = 64 << 20
)

// DecompressContainer expands a Windows Compression API LZMS container in
// memory. The declared total is checked against maximumOutputSize before any
// output allocation or chunk decompression occurs.
func DecompressContainer(data []byte, maximumOutputSize uint64) ([]byte, error) {
	if len(data) < compressionAPIHeaderSize {
		return nil, fmt.Errorf("lzms: container has %d bytes, need at least %d", len(data), compressionAPIHeaderSize)
	}
	if magic := binary.LittleEndian.Uint32(data[0:4]); magic != CompressionAPIMagic {
		return nil, fmt.Errorf("lzms: invalid container magic %#x", magic)
	}
	headerSize := int(binary.LittleEndian.Uint16(data[4:6]))
	if headerSize < compressionAPIHeaderSize || headerSize > len(data) {
		return nil, fmt.Errorf("lzms: invalid container header size %d", headerSize)
	}
	if actual, expected := containerHeaderCRC(data[:headerSize]), data[6]; actual != expected {
		return nil, fmt.Errorf("lzms: container header CRC %#x does not match %#x", actual, expected)
	}
	if algorithm := data[7]; algorithm != compressionAPIAlgorithm {
		return nil, fmt.Errorf("lzms: unsupported container algorithm %d", algorithm)
	}
	total := binary.LittleEndian.Uint64(data[8:16])
	if total > maximumOutputSize {
		return nil, fmt.Errorf("lzms: container output size %d exceeds limit %d", total, maximumOutputSize)
	}
	if total > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("lzms: container output size %d is too large", total)
	}
	chunkSize := binary.LittleEndian.Uint32(data[16:20])
	if chunkSize == 0 || chunkSize > maximumContainerChunk {
		return nil, fmt.Errorf("lzms: invalid container chunk size %d", chunkSize)
	}
	if flags := binary.LittleEndian.Uint32(data[20:24]); flags != 0 {
		return nil, fmt.Errorf("lzms: unsupported container flags %#x", flags)
	}

	output := make([]byte, 0, int(total))
	offset := headerSize
	for uint64(len(output)) < total {
		if len(data)-offset < 4 {
			return nil, fmt.Errorf("lzms: truncated container chunk header at %#x", offset)
		}
		compressedSize := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
		remaining := total - uint64(len(output))
		uncompressedSize := min(uint64(chunkSize), remaining)
		if compressedSize == 0 || uint64(compressedSize) > uncompressedSize {
			return nil, fmt.Errorf("lzms: invalid compressed chunk size %d for %d output bytes", compressedSize, uncompressedSize)
		}
		if uint64(compressedSize) > uint64(len(data)-offset) {
			return nil, fmt.Errorf("lzms: truncated container chunk at %#x", offset)
		}
		chunk := data[offset : offset+int(compressedSize)]
		offset += int(compressedSize)
		if uint64(compressedSize) == uncompressedSize {
			output = append(output, chunk...)
			continue
		}
		decoded, err := Decompress(chunk, int(uncompressedSize))
		if err != nil {
			return nil, fmt.Errorf("lzms: container chunk at output offset %#x: %w", len(output), err)
		}
		output = append(output, decoded...)
	}
	if offset != len(data) {
		return nil, fmt.Errorf("lzms: container has %d trailing bytes", len(data)-offset)
	}
	return output, nil
}

func containerHeaderCRC(header []byte) byte {
	checksum := crc32.NewIEEE()
	_, _ = checksum.Write(header[:6])
	_, _ = checksum.Write(header[7:])
	return byte(checksum.Sum32())
}
