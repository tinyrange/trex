package lzx

import (
	"fmt"
	"io"
)

const lzxInputBufferSize = 64 << 10

// refill preserves the reservoir, which may contain words from the previous
// input buffer. Raw reads rewind those words, possibly before this buffer's base.
func (r *lzxBitReader) refill(need int) bool {
	if r.err != nil {
		return false
	}
	off := r.base + int64(r.pos)
	if need < 0 || off < 0 || off > r.size || int64(need) > r.size-off {
		// A single trailing byte cannot form an LZX word. Leave the reservoir
		// available to decode any complete codes already fetched before EOF.
		return false
	}
	size := int(min(int64(max(lzxInputBufferSize, need)), r.size-off))
	if cap(r.buffer) < size {
		r.buffer = make([]byte, size)
	}
	data := r.buffer[:size]
	n, err := r.reader.ReadAt(data, off)
	if n != size || (err != nil && err != io.EOF) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		r.err = fmt.Errorf("lzx: input at %d: %w", off, err)
		return false
	}
	r.base, r.pos, r.data = off, 0, data
	return true
}

// DecompressReaderTo decodes a CAB LZX stream from stable random-access input.
// Neither the full compressed stream nor the expanded output is retained.
// Ordinary input buffering is 64 KiB; an uncompressed format block can require
// up to its 24-bit size. Output/history and failure semantics match DecompressTo.
// The source must remain unchanged until this call returns.
func DecompressReaderTo(dst io.Writer, source io.ReaderAt, compressedSize int64, windowBits, outSize int) error {
	if source == nil || compressedSize < 0 || compressedSize > int64(int(^uint(0)>>1)) {
		return fmt.Errorf("lzx: invalid compressed source or size")
	}
	return decompressTo(dst, &lzxBitReader{reader: source, size: compressedSize}, windowBits, outSize)
}
