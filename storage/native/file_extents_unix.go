//go:build linux || darwin || freebsd

package native

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// Extents reports allocation on the same open inode used by ReadAt. Positioned
// reads are independent of the offset used by SEEK_DATA and SEEK_HOLE.
func (f *osFile) Extents(off, length int64) ([]BlockExtent, error) {
	if err := validateBlockRange(f.size, off, length); err != nil {
		return nil, err
	}
	var out []BlockExtent
	end := off + length
	for pos := off; pos < end; {
		data, err := f.file.Seek(pos, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			return append(out, BlockExtent{Offset: pos, Length: end - pos}), nil
		}
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
			return []BlockExtent{{Offset: off, Length: length, Allocated: true}}, nil
		}
		if err != nil {
			return nil, err
		}
		if data < pos {
			return nil, fmt.Errorf("file: allocation map moved backwards at %d", pos)
		}
		data = min(data, end)
		if data > pos {
			out = append(out, BlockExtent{Offset: pos, Length: data - pos})
		}
		if data == end {
			break
		}
		hole, err := f.file.Seek(data, unix.SEEK_HOLE)
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
			return []BlockExtent{{Offset: off, Length: length, Allocated: true}}, nil
		}
		if err != nil {
			return nil, err
		}
		if hole <= data {
			return nil, fmt.Errorf("file: invalid data extent at %d", data)
		}
		pos = min(hole, end)
		out = append(out, BlockExtent{Offset: data, Length: pos - data, Allocated: true})
	}
	return out, nil
}
