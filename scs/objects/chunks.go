package objects

import (
	"context"
	"errors"
	"io"
	"math"
	"sort"

	"github.com/tinyrange/trex/storage"
)

type Chunk struct {
	ID   ID
	Kind byte
	Size int64
}
type chunked struct {
	chunks []storage.Reader
	starts []int64
	size   int64
}

// ChunkedReader accepts a caller-authenticated manifest, not an unverified
// remote path listing. Chunks are individually verified when read. Its retained
// memory includes the manifest; the cache limit is not a total RAM guarantee.
func (c *Cache) ChunkedReader(ctx context.Context, chunks []Chunk) (storage.Reader, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(chunks) > 1000000 {
		return nil, ErrLimit
	}
	r := &chunked{}
	for _, chunk := range chunks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if chunk.Size <= 0 || chunk.Size > math.MaxInt64-r.size {
			return nil, errors.New("invalid chunk manifest")
		}
		reader, err := c.Reader(ctx, chunk.ID, chunk.Kind, chunk.Size)
		if err != nil {
			return nil, err
		}
		r.starts = append(r.starts, r.size)
		r.chunks = append(r.chunks, reader)
		r.size += chunk.Size
	}
	return r, nil
}
func (r *chunked) Size() int64 { return r.size }
func (r *chunked) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.size {
		return 0, io.EOF
	}
	n := 0
	index := sort.Search(len(r.starts), func(i int) bool { return r.starts[i] > off }) - 1
	for len(p) > 0 && off < r.size {
		chunk := r.chunks[index]
		offset := off - r.starts[index]
		amount := min(int64(len(p)), chunk.Size()-offset)
		got, err := chunk.ReadAt(p[:amount], offset)
		n += got
		off += int64(got)
		p = p[got:]
		if err != nil {
			return n, err
		}
		if int64(got) != amount {
			return n, io.ErrUnexpectedEOF
		}
		index++
	}
	if len(p) > 0 {
		return n, io.EOF
	}
	return n, nil
}
