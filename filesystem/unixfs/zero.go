package unixfs

import (
	"fmt"
	"io"
)

// Zero is a bounded sparse zero reader; no allocation depends on its size.
type Zero int64

func (z Zero) Size() int64 { return int64(z) }
func (z Zero) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= int64(z) {
		return 0, io.EOF
	}
	n := int(min(int64(len(p)), int64(z)-off))
	clear(p[:n])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
