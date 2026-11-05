package sevenzip

import "io"

// NewBCJ2Reader decodes four bounded BCJ2 streams (main, calls, jumps, range)
// to exactly size bytes. Read through EOF to validate complete consumption and
// range termination. This primitive is shared by 7z folders and Omaha payloads.
func NewBCJ2Reader(inputs []io.Reader, sizes []uint64, size uint64) (io.Reader, error) {
	return newBCJ2Reader(inputs, sizes, size)
}
