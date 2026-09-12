package ods2

import (
	"fmt"
	"io"
	"sort"

	"github.com/tinyrange/trex/storage"
)

type mappedExtent struct{ logical, physical, length int64 }

// File is a read-only logical view over validated allocation extents. It does
// not copy file contents or expose allocation slack past the logical EOF.
type File struct {
	base    storage.Reader
	extents []mappedExtent
	size    int64
}

func MapFile(base storage.Reader, extents []Extent, size int64) (*File, error) {
	if size < 0 || base.Size() < 0 {
		return nil, fmt.Errorf("ods2: invalid file size")
	}
	f := &File{base: base, size: size}
	var logical int64
	for _, e := range extents {
		physical, length := int64(e.LBN)*BlockSize, int64(e.Blocks)*BlockSize
		if length == 0 || physical > base.Size() || length > base.Size()-physical {
			return nil, fmt.Errorf("ods2: extent outside image")
		}
		if logical > int64(^uint64(0)>>1)-length {
			return nil, fmt.Errorf("ods2: allocation size overflow")
		}
		f.extents = append(f.extents, mappedExtent{logical: logical, physical: physical, length: length})
		logical += length
	}
	if size > logical {
		return nil, fmt.Errorf("ods2: logical EOF exceeds mapped allocation")
	}
	return f, nil
}
func (f *File) Size() int64                        { return f.size }
func (f *File) WriteAt([]byte, int64) (int, error) { return 0, fmt.Errorf("ods2: read-only file") }
func (f *File) ReadAt(p []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, fmt.Errorf("ods2: negative file offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if offset >= f.size {
		return 0, io.EOF
	}
	wanted := len(p)
	if int64(len(p)) > f.size-offset {
		p = p[:f.size-offset]
	}
	total := 0
	index := sort.Search(len(f.extents), func(i int) bool { return f.extents[i].logical+f.extents[i].length > offset })
	for len(p) > 0 {
		if index >= len(f.extents) {
			return total, io.ErrUnexpectedEOF
		}
		e := f.extents[index]
		relative := offset - e.logical
		n := len(p)
		if int64(n) > e.length-relative {
			n = int(e.length - relative)
		}
		got, err := f.base.ReadAt(p[:n], e.physical+relative)
		total += got
		if got != n {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return total, err
		}
		if err != nil && err != io.EOF {
			return total, err
		}
		p = p[n:]
		offset += int64(n)
		index++
	}
	if total < wanted {
		return total, io.EOF
	}
	return total, nil
}
