package lzms

import (
	"github.com/tinyrange/trex/compression/internal/wincontainer"
	"hash/crc32"
)

const (
	CompressionAPIMagic      = wincontainer.CompressionAPIMagic
	compressionAPIHeaderSize = 24
	compressionAPIAlgorithm  = 5
)

// DecompressContainer expands a bounded Windows Compression API LZMS frame.
func DecompressContainer(data []byte, maximumOutputSize uint64) ([]byte, error) {
	return wincontainer.DecodeInto(data, maximumOutputSize, compressionAPIAlgorithm, decompressInto)
}

func containerHeaderCRC(header []byte) byte {
	checksum := crc32.NewIEEE()
	_, _ = checksum.Write(header[:6])
	_, _ = checksum.Write(header[7:])
	return byte(checksum.Sum32())
}
