package cpio

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
)

const metadataBuffer = 64 << 10

// metadataReader reads monotonically with bounded lookahead. Slices remain
// valid until the next read. Large file payloads are skipped, never copied.
// Sliding a partial window avoids backwards reads even for long names/links
// that cross a window boundary on a replaying compressed reader.
type metadataReader struct {
	source     storage.Reader
	size, base int64
	data       []byte
}

func (r *metadataReader) read(off, n int64) ([]byte, error) {
	if off < 0 || n < 0 || off > r.size || n > r.size-off || n > metadataBuffer {
		return nil, io.ErrUnexpectedEOF
	}
	if n == 0 {
		return nil, nil
	}
	end := r.base + int64(len(r.data))
	if off >= r.base && off+n <= end {
		return r.data[off-r.base : off-r.base+n], nil
	}
	if off < r.base {
		return nil, fmt.Errorf("cpio: non-monotonic metadata read")
	}
	retained := 0
	if off < end {
		retained = copy(r.data, r.data[off-r.base:])
	}
	if cap(r.data) == 0 {
		r.data = make([]byte, metadataBuffer)
	}
	r.base = off
	length := int(min(int64(metadataBuffer), r.size-off))
	r.data = r.data[:length]
	if _, err := io.ReadFull(io.NewSectionReader(r.source, off+int64(retained), int64(length-retained)), r.data[retained:]); err != nil {
		return nil, err
	}
	return r.data[:n], nil
}
