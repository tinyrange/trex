package filesystem

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/tinyrange/trex/block"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type imageExtent struct {
	start int64
	size  int64
	data  []byte
	file  starfile.File
	off   int64
}

type generatedImageFile struct {
	name      string
	size      int64
	extents   []imageExtent
	indexOnce sync.Once
	indexErr  error
}

func (f *generatedImageFile) ensureIndexed() error {
	f.indexOnce.Do(func() {
		if f.size < 0 {
			f.indexErr = fmt.Errorf("%s: negative image size %d", f.name, f.size)
			return
		}
		extents := make([]imageExtent, 0, len(f.extents))
		for _, extent := range f.extents {
			if extent.size == 0 {
				continue
			}
			if extent.start < 0 || extent.size < 0 || extent.start > f.size || extent.size > f.size-extent.start {
				f.indexErr = fmt.Errorf("%s: extent [%d,%d) is outside image size %d", f.name, extent.start, extent.start+extent.size, f.size)
				return
			}
			if extent.file == nil && extent.data != nil && int64(len(extent.data)) < extent.size {
				f.indexErr = fmt.Errorf("%s: extent [%d,%d) has only %d data bytes", f.name, extent.start, extent.start+extent.size, len(extent.data))
				return
			}
			extents = append(extents, extent)
		}
		sort.SliceStable(extents, func(i, j int) bool { return extents[i].start < extents[j].start })
		for i := 1; i < len(extents); i++ {
			previous := extents[i-1]
			if extents[i].start < previous.start+previous.size {
				f.indexErr = fmt.Errorf("%s: overlapping extents [%d,%d) and [%d,%d)", f.name, previous.start, previous.start+previous.size, extents[i].start, extents[i].start+extents[i].size)
				return
			}
		}
		f.extents = extents
	})
	return f.indexErr
}

func (f *generatedImageFile) ReadAt(p []byte, off int64) (int, error) {
	if err := f.ensureIndexed(); err != nil {
		return 0, err
	}
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.size {
		return 0, io.EOF
	}
	remaining := int64(len(p))
	if remaining > f.size-off {
		remaining = f.size - off
	}
	read := int64(0)
	extentIndex := sort.Search(len(f.extents), func(i int) bool {
		return f.extents[i].start+f.extents[i].size > off
	})
	for read < remaining {
		pos := off + read
		n := remaining - read
		if extentIndex < len(f.extents) {
			extent := f.extents[extentIndex]
			if pos < extent.start {
				if n > extent.start-pos {
					n = extent.start - pos
				}
				clear(p[read : read+n])
				read += n
				continue
			}
			if pos < extent.start+extent.size {
				within := pos - extent.start
				if limit := extent.size - within; n > limit {
					n = limit
				}
				if extent.file != nil {
					got, err := extent.file.ReadAt(p[read:read+n], extent.off+within)
					read += int64(got)
					if got == 0 && err == nil {
						return int(read), io.ErrNoProgress
					}
					if err != nil && !(err == io.EOF && int64(got) == n) {
						return int(read), err
					}
				} else {
					if extent.data == nil {
						clear(p[read : read+n])
					} else {
						copy(p[read:read+n], extent.data[within:within+n])
					}
					read += n
				}
				if off+read >= extent.start+extent.size {
					extentIndex++
				}
				continue
			}
		}
		clear(p[read : read+n])
		read += n
	}
	if int64(len(p)) > read {
		return int(read), io.EOF
	}
	return int(read), nil
}
func (f *generatedImageFile) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("%s is read-only", f.name)
}

func (f *generatedImageFile) Extents(off, length int64) ([]block.Extent, error) {
	if err := f.ensureIndexed(); err != nil {
		return nil, err
	}
	if err := validateBlockRange(f.size, off, length); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	end := off + length
	position := off
	index := sort.Search(len(f.extents), func(i int) bool {
		return f.extents[i].start+f.extents[i].size > off
	})
	out := make([]block.Extent, 0, 4)
	appendExtent := func(offset, size int64, allocated bool) {
		if size <= 0 {
			return
		}
		if len(out) > 0 {
			last := &out[len(out)-1]
			if last.Offset+last.Length == offset && last.Allocated == allocated {
				last.Length += size
				return
			}
		}
		out = append(out, block.Extent{Offset: offset, Length: size, Allocated: allocated})
	}
	for position < end {
		if index >= len(f.extents) || f.extents[index].start >= end {
			appendExtent(position, end-position, false)
			break
		}
		extent := f.extents[index]
		if position < extent.start {
			gapEnd := minImageInt64(end, extent.start)
			appendExtent(position, gapEnd-position, false)
			position = gapEnd
			continue
		}
		extentEnd := minImageInt64(end, extent.start+extent.size)
		within := position - extent.start
		segmentSize := extentEnd - position
		if provider, ok := extent.file.(blockDeviceExtenter); ok {
			sourceOffset := extent.off + within
			sourceExtents, err := provider.Extents(sourceOffset, segmentSize)
			if err != nil {
				return nil, err
			}
			expected := sourceOffset
			for _, sourceExtent := range sourceExtents {
				if sourceExtent.Length <= 0 || sourceExtent.Offset != expected || sourceExtent.Length > sourceOffset+segmentSize-expected {
					return nil, fmt.Errorf("%s: nested extent map does not cover requested range", f.name)
				}
				appendExtent(position+(sourceExtent.Offset-sourceOffset), sourceExtent.Length, sourceExtent.Allocated)
				expected += sourceExtent.Length
			}
			if expected != sourceOffset+segmentSize {
				return nil, fmt.Errorf("%s: nested extent map does not cover requested range", f.name)
			}
		} else {
			appendExtent(position, segmentSize, extent.file != nil || extent.data != nil)
		}
		position = extentEnd
		if position >= extent.start+extent.size {
			index++
		}
	}
	return out, nil
}

func (f *generatedImageFile) WriteTo(w io.Writer) (int64, error) {
	if err := f.ensureIndexed(); err != nil {
		return 0, err
	}
	written := int64(0)
	for _, extent := range f.extents {
		if extent.start > written {
			n, err := writeImageGap(w, extent.start-written)
			written += n
			if err != nil {
				return written, err
			}
		}
		within := int64(0)
		size := extent.size
		var err error
		var n int64
		switch {
		case extent.file != nil:
			err = writeFileRangeTo(w, extent.file, extent.off+within, size)
			if err == nil {
				n = size
			}
		case extent.data != nil:
			n, err = io.Copy(w, bytes.NewReader(extent.data[within:within+size]))
		default:
			n, err = writeZerosTo(w, size)
		}
		written += n
		if err != nil {
			return written, err
		}
		if n != size {
			return written, io.ErrShortWrite
		}
	}
	if written < f.size {
		n, err := writeImageGap(w, f.size-written)
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func writeImageGap(w io.Writer, size int64) (int64, error) {
	if size <= 0 {
		return 0, nil
	}
	if seeker, ok := w.(io.WriteSeeker); ok {
		// A seek beyond EOF does not extend a regular file. Materialize only the
		// final byte of the hole so sparse outputs retain their logical size.
		if _, err := seeker.Seek(size-1, io.SeekCurrent); err == nil {
			n, writeErr := seeker.Write([]byte{0})
			advanced := size - 1 + int64(n)
			if writeErr != nil {
				return advanced, writeErr
			}
			if n != 1 {
				return advanced, io.ErrShortWrite
			}
			return size, nil
		}
	}
	return writeZerosTo(w, size)
}
func (f *generatedImageFile) Size() int64 { return f.size }
func (f *generatedImageFile) String() string {
	return fmt.Sprintf("<file %q size=%d>", f.name, f.size)
}
func (f *generatedImageFile) Type() string         { return "file" }
func (f *generatedImageFile) Freeze()              {}
func (f *generatedImageFile) Truth() starlark.Bool { return starlark.True }
func (f *generatedImageFile) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *generatedImageFile) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *generatedImageFile) AttrNames() []string { return starfile.AttrNames() }

func minImageInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
