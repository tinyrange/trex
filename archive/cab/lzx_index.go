package cab

import (
	"fmt"
	"io"
	"sync"

	"github.com/tinyrange/trex/compression/lzx"
)

type indexedLZXFolder struct {
	mu     sync.Mutex
	reader *lzx.IndexedReader
	err    error
}

func (f *Entry) indexedLZX() bool {
	return f.archive.lzxCheckpointBytes > 0 && int(f.file.folder) < len(f.archive.folders) && f.archive.folders[f.file.folder].compression&0xf == 3
}
func (c *Archive) indexedLZXFolders() []indexedLZXFolder {
	c.lzxOnce.Do(func() { c.lzxFolders = make([]indexedLZXFolder, len(c.folders)) })
	return c.lzxFolders
}
func (c *Archive) indexedLZXFolder(index int) (*lzx.IndexedReader, error) {
	x := &c.indexedLZXFolders()[index]
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.reader != nil || x.err != nil {
		return x.reader, x.err
	}
	folder := c.folders[index]
	source, size, err := c.folderPayloadReader(folder)
	if err != nil {
		x.err = err
		return nil, err
	}
	if size == 0 {
		for _, f := range c.files {
			if f.folder == 0 {
				size += int(f.size)
			}
		}
	}
	x.reader, x.err = lzx.NewIndexedReader(source, source.Size(), int(folder.compression>>8), size, c.lzxCheckpointBytes)
	return x.reader, x.err
}
func (f *Entry) readIndexedLZXAt(p []byte, off int64) (int, error) {
	r, err := f.archive.indexedLZXFolder(int(f.file.folder))
	if err != nil {
		return 0, err
	}
	start, size := int64(f.file.uncompressedStart), f.Size()
	if start > r.Size() || size > r.Size()-start {
		return 0, fmt.Errorf("cab: member %q exceeds indexed folder", f.file.name)
	}
	return io.NewSectionReader(r, start, size).ReadAt(p, off)
}
