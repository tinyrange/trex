package cab

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"sync"
)

// Uncompressed folders are already random-access data. Index only CFDATA
// extents; retaining a decoded copy can pin a whole outer cabinet merely to
// read the header of a nested archive. The source has the same immutable
// lifetime contract as compressed archive readers.
type rawBlock struct{ offset, start, size int64 }
type rawFolderIndex struct {
	once   sync.Once
	blocks []rawBlock
	size   int64
	err    error
}

func (f *Entry) raw() bool {
	return int(f.file.folder) < len(f.archive.folders) && f.archive.folders[f.file.folder].compression&0xf == 0
}

func (c *Archive) rawFolder(index int) (*rawFolderIndex, error) {
	c.rawOnce.Do(func() { c.rawFolders = make([]rawFolderIndex, len(c.folders)) })
	result := &c.rawFolders[index]
	result.once.Do(func() {
		folder := c.folders[index]
		offset := int64(folder.dataOffset)
		header := make([]byte, 8+c.dataReserve)
		blocks := make([]rawBlock, 0, folder.blocks)
		var total, pending int64
		for i := 0; i < int(folder.blocks); i++ {
			if offset < 0 || offset > c.file.Size()-int64(len(header)) {
				result.err = fmt.Errorf("cab: raw folder header exceeds source")
				return
			}
			if _, err := c.file.ReadAt(header, offset); err != nil {
				result.err = err
				return
			}
			size := int64(binary.LittleEndian.Uint16(header[4:6]))
			decoded := int64(binary.LittleEndian.Uint16(header[6:8]))
			offset += int64(len(header))
			if size > c.file.Size()-offset {
				result.err = fmt.Errorf("cab: raw folder block exceeds source")
				return
			}
			if size != 0 {
				blocks = append(blocks, rawBlock{offset, total, size})
			}
			total += size
			pending += size
			if decoded != 0 {
				if pending != decoded {
					result.err = fmt.Errorf("cab: raw folder block length mismatch")
					return
				}
				pending = 0
			}
			offset += size
		}
		if pending != 0 {
			result.err = fmt.Errorf("cab: unterminated split data block")
			return
		}
		result.blocks, result.size = blocks, total
	})
	return result, result.err
}

func (f *Entry) readRawAt(p []byte, off int64) (int, error) {
	index, err := f.archive.rawFolder(int(f.file.folder))
	if err != nil {
		return 0, err
	}
	start, size := int64(f.file.uncompressedStart), f.Size()
	if start > index.size || size > index.size-start {
		return 0, fmt.Errorf("cab: file %q extends past folder data", f.file.name)
	}
	count := len(p)
	if int64(count) > size-off {
		count = int(size - off)
	}
	position := start + off
	block := sort.Search(len(index.blocks), func(i int) bool { b := index.blocks[i]; return b.start+b.size > position })
	read := 0
	for read < count {
		if block >= len(index.blocks) {
			return read, io.ErrUnexpectedEOF
		}
		b := index.blocks[block]
		skip := position - b.start
		n := min(int(b.size-skip), count-read)
		got, err := f.archive.file.ReadAt(p[read:read+n], b.offset+skip)
		read += got
		position += int64(got)
		if got != n {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return read, err
		}
		if err != nil && err != io.EOF {
			return read, err
		}
		block++
	}
	if read < len(p) {
		return read, io.EOF
	}
	return read, nil
}
