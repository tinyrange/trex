// Package pbze reads Apple's LZFSE-framed parallel compression streams.
// The framing is a magic, a big-endian u64 chunk bound, and pairs of decoded
// and stored u64 lengths. Each unequal-length chunk is an independent LZFSE
// stream. Sources remain borrowed; decoding uses a bounded volatile cache.
package pbze

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sort"

	"github.com/tinyrange/trex/archive/lzfse"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
)

const maxChunk = 64 << 20
const maxChunks = 100000

type chunk struct {
	offset, stored, start, size int64
}

type File struct {
	source storage.Reader
	chunks []chunk
	size   int64
	cache  *bytecache.Cache
}

func (f *File) Size() int64 { return f.size }

func Open(source storage.Reader, maximum int64) (*File, error) {
	if source == nil || source.Size() < 12 || maximum < 0 {
		return nil, fmt.Errorf("pbze: invalid source or maximum")
	}
	if maximum == 0 {
		maximum = math.MaxInt64
	}
	var h [16]byte
	if _, err := source.ReadAt(h[:12], 0); err != nil {
		return nil, err
	}
	bound := binary.BigEndian.Uint64(h[4:12])
	if string(h[:4]) != "pbze" || bound == 0 || bound > maxChunk {
		return nil, fmt.Errorf("pbze: invalid header or chunk bound")
	}
	f := &File{source: source, cache: bytecache.New(maxChunk)}
	for off := int64(12); off < source.Size(); {
		if source.Size()-off < 16 || len(f.chunks) == maxChunks {
			return nil, fmt.Errorf("pbze: truncated or excessive chunk headers")
		}
		if _, err := source.ReadAt(h[:], off); err != nil {
			return nil, err
		}
		decoded, stored := binary.BigEndian.Uint64(h[:8]), binary.BigEndian.Uint64(h[8:])
		off += 16
		if decoded == 0 || decoded > bound || stored == 0 || stored > maxChunk || stored > uint64(source.Size()-off) || decoded > uint64(maximum-f.size) {
			return nil, fmt.Errorf("pbze: invalid chunk bounds")
		}
		c := chunk{off, int64(stored), f.size, int64(decoded)}
		if stored != decoded {
			r, err := lzfse.Open(io.NewSectionReader(source, off, c.stored), c.size)
			if err != nil {
				return nil, fmt.Errorf("pbze: chunk %d: %w", len(f.chunks), err)
			}
			if r.Size() != c.size {
				return nil, fmt.Errorf("pbze: decoded length mismatch")
			}
		}
		f.chunks = append(f.chunks, c)
		f.size += c.size
		off += c.stored
		if decoded < bound && off != source.Size() {
			return nil, fmt.Errorf("pbze: data after final short chunk")
		}
	}
	if len(f.chunks) == 0 {
		return nil, fmt.Errorf("pbze: no chunks")
	}
	return f, nil
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("pbze: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.size {
		return 0, io.EOF
	}
	wanted, done := len(p), 0
	p = p[:min(int64(len(p)), f.size-off)]
	i := sort.Search(len(f.chunks), func(i int) bool { return f.chunks[i].start+f.chunks[i].size > off })
	for len(p) != 0 {
		c := f.chunks[i]
		skip, n := off-c.start, min(int64(len(p)), c.start+c.size-off)
		if c.stored == c.size {
			if _, err := io.ReadFull(io.NewSectionReader(f.source, c.offset+skip, n), p[:n]); err != nil {
				return done, err
			}
		} else {
			data, err := f.cache.Get(bytecache.Key{Index: i}, func() ([]byte, error) {
				r, err := lzfse.Open(io.NewSectionReader(f.source, c.offset, c.stored), c.size)
				if err != nil {
					return nil, err
				}
				data := make([]byte, c.size)
				_, err = io.ReadFull(io.NewSectionReader(r, 0, c.size), data)
				return data, err
			})
			if err != nil {
				return done, fmt.Errorf("pbze: chunk %d: %w", i, err)
			}
			copy(p[:n], data[skip:skip+n])
		}
		done += int(n)
		off += n
		p = p[n:]
		i++
	}
	if done < wanted {
		return done, io.EOF
	}
	return done, nil
}
