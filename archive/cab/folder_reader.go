package cab

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/tinyrange/trex/storage"
)

// folderPayloadReader joins only the compressed CFDATA extents. Headers and
// reserves are excluded, and no compressed or expanded folder copy is retained.
// This preserves the existing decoder's split-block and checksum semantics.
type folderPayloadReader struct {
	source storage.Reader
	blocks []rawBlock
	size   int64
}

func (r *folderPayloadReader) Size() int64 { return r.size }
func (r *folderPayloadReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("cab: negative payload offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.size {
		return 0, io.EOF
	}
	count := int(min(int64(len(p)), r.size-off))
	block := sort.Search(len(r.blocks), func(i int) bool { b := r.blocks[i]; return b.start+b.size > off })
	done := 0
	for done < count {
		if block >= len(r.blocks) {
			return done, io.ErrUnexpectedEOF
		}
		b := r.blocks[block]
		skip := off - b.start
		want := int(min(b.size-skip, int64(count-done)))
		n, err := r.source.ReadAt(p[done:done+want], b.offset+skip)
		done += n
		off += int64(n)
		if n != want {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return done, err
		}
		if err != nil && err != io.EOF {
			return done, err
		}
		block++
	}
	if done < len(p) {
		return done, io.EOF
	}
	return done, nil
}
func (c *Archive) folderPayloadReader(folder folder) (*folderPayloadReader, int, error) {
	r := &folderPayloadReader{source: c.file, blocks: make([]rawBlock, 0, int(folder.blocks))}
	totalOutput := 0
	offset := int64(folder.dataOffset)
	headerSize := 8 + c.dataReserve
	header := make([]byte, headerSize)
	maximum := int(^uint(0) >> 1)
	for i := 0; i < int(folder.blocks); i++ {
		if offset < 0 || offset > c.file.Size() || int64(headerSize) > c.file.Size()-offset {
			return nil, 0, io.ErrUnexpectedEOF
		}
		if _, err := c.file.ReadAt(header, offset); err != nil {
			return nil, 0, err
		}
		offset += int64(headerSize)
		size := int64(binary.LittleEndian.Uint16(header[4:6]))
		expanded := int(binary.LittleEndian.Uint16(header[6:8]))
		if size > c.file.Size()-offset {
			return nil, 0, io.ErrUnexpectedEOF
		}
		if size > int64(maximum)-r.size || expanded > maximum-totalOutput {
			return nil, 0, fmt.Errorf("cab: folder size overflow")
		}
		if size != 0 {
			r.blocks = append(r.blocks, rawBlock{offset, r.size, size})
		}
		r.size += size
		totalOutput += expanded
		offset += size
	}
	return r, totalOutput, nil
}
