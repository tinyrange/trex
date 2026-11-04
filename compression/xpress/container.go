package xpress

import "github.com/tinyrange/trex/compression/internal/wincontainer"

// DecompressContainer expands a bounded Windows Compression API XPRESS Huffman frame.
func DecompressContainer(data []byte, maximumOutputSize uint64) ([]byte, error) {
	return wincontainer.Decode(data, maximumOutputSize, 4, HuffmanDecompress)
}
