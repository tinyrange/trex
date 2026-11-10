package cab

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/tinyrange/trex/compression/mszip"
)

const mszipCheckpointStride = 32

type mszipBlock struct {
	offset, start       int64
	compressed, decoded int
}
type mszipFolderIndex struct {
	once     sync.Once
	mu       sync.Mutex
	blocks   []mszipBlock
	size     int64
	err      error
	fallback bool
	// Each checkpoint is the 32-KiB dictionary before that block. Retain one
	// per MiB of normal output, not the entire expanded outer cabinet.
	checkpoints   map[int][]byte
	last          int
	data, history []byte
	encoded       []byte
	decoder       *mszip.Decoder
}

func (f *Entry) indexedMSZIP() bool {
	if int(f.file.folder) >= len(f.archive.folders) {
		return false
	}
	folder := f.archive.folders[f.file.folder]
	return f.archive.cache && folder.compression&0xf == 1 && folder.blocks >= 256
}
func (c *Archive) mszipFolder(index int) *mszipFolderIndex {
	c.mszipOnce.Do(func() { c.mszipFolders = make([]mszipFolderIndex, len(c.folders)) })
	result := &c.mszipFolders[index]
	result.once.Do(func() {
		result.last = -1
		result.checkpoints = map[int][]byte{0: nil}
		folder := c.folders[index]
		offset := int64(folder.dataOffset)
		header := make([]byte, 8+c.dataReserve)
		for i := 0; i < int(folder.blocks); i++ {
			if offset < 0 || offset > c.file.Size()-int64(len(header)) {
				result.err = fmt.Errorf("cab: MSZIP header exceeds source")
				return
			}
			if _, err := c.file.ReadAt(header, offset); err != nil {
				result.err = err
				return
			}
			offset += int64(len(header))
			compressed := int(binary.LittleEndian.Uint16(header[4:]))
			decoded := int(binary.LittleEndian.Uint16(header[6:]))
			if int64(compressed) > c.file.Size()-offset {
				result.err = fmt.Errorf("cab: MSZIP block exceeds source")
				return
			}
			if decoded == 0 {
				result.fallback = true
			} // Physical split blocks use the existing set/stream decoder.
			result.blocks = append(result.blocks, mszipBlock{offset, result.size, compressed, decoded})
			result.size += int64(decoded)
			offset += int64(compressed)
		}
	})
	return result
}
func (x *mszipFolderIndex) block(c *Archive, target int) ([]byte, error) {
	if target == x.last {
		return x.data, nil
	}
	start := target - target%mszipCheckpointStride
	for start > 0 {
		if _, ok := x.checkpoints[start]; ok {
			break
		}
		start -= mszipCheckpointStride
	}
	history := x.checkpoints[start]
	if x.last >= start && x.last < target {
		start = x.last + 1
		history = x.history
	}
	// Keep history separate from the decoder's borrowed output, and invalidate
	// the one-block hit before any scratch can be overwritten by a failed seek.
	x.history = append(x.history[:0], history...)
	history = x.history
	x.last = -1
	for i := start; i <= target; i++ {
		b := x.blocks[i]
		if cap(x.encoded) < b.compressed {
			x.encoded = make([]byte, b.compressed)
		}
		encoded := x.encoded[:b.compressed]
		if _, err := c.file.ReadAt(encoded, b.offset); err != nil {
			return nil, err
		}
		if len(encoded) < 2 || string(encoded[:2]) != "CK" {
			return nil, fmt.Errorf("cab: invalid MSZIP block")
		}
		x.last = -1
		if x.decoder == nil {
			x.decoder = &mszip.Decoder{}
		}
		data, err := x.decoder.Decode(encoded[2:], history, b.decoded)
		if err != nil {
			return nil, err
		}
		if len(data) >= 32768 {
			history = append(history[:0], data[len(data)-32768:]...)
		} else {
			keep := min(len(history), 32768-len(data))
			copy(history, history[len(history)-keep:])
			history = append(history[:keep], data...)
		}
		if (i+1)%mszipCheckpointStride == 0 {
			if _, ok := x.checkpoints[i+1]; !ok {
				x.checkpoints[i+1] = bytes.Clone(history)
			}
		}
		x.last, x.data, x.history = i, data, history
	}
	return x.data, nil
}
func (f *Entry) readMSZIPAt(p []byte, off int64) (int, error) {
	x := f.archive.mszipFolder(int(f.file.folder))
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.err != nil {
		return 0, x.err
	}
	if !x.fallback {
		start, size := int64(f.file.uncompressedStart), f.Size()
		if start > x.size || size > x.size-start {
			return 0, fmt.Errorf("cab: file %q extends past folder data", f.file.name)
		}
		count := min(int64(len(p)), size-off)
		position := start + off
		block := sort.Search(len(x.blocks), func(i int) bool { b := x.blocks[i]; return b.start+int64(b.decoded) > position })
		read := 0
		for int64(read) < count {
			data, err := x.block(f.archive, block)
			if err != nil {
				// Some legacy cabinets continue one deflate stream across CFDATA.
				// Retry with the existing whole-stream validator, never partial bytes.
				x.fallback = true
				x.checkpoints, x.data, x.history = nil, nil, nil
				x.decoder, x.encoded = nil, nil
				break
			}
			skip := position - x.blocks[block].start
			n := copy(p[read:int(count)], data[skip:])
			read += n
			position += int64(n)
			block++
		}
		if !x.fallback {
			if read < len(p) {
				return read, io.EOF
			}
			return read, nil
		}
	}
	data, err := f.archive.fileData(f.file)
	if err != nil {
		return 0, err
	}
	n := copy(p, data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
