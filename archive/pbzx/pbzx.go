// Package pbzx reads Apple's chunked installer payload streams without a host
// extractor or materialized intermediate. Chunk headers give decoded and stored
// sizes; unequal sizes wrap an independently checked XZ stream.
package pbzx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/archive/xz"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	"io"
	"math"
	"sort"
	"sync/atomic"
)

const MaxChunk = 64 << 20
const MaxChunks = 100000

// Chunk retains physical and logical extents without decoding its bytes.
type Chunk struct {
	Offset, Length, Start, Size int64
	Compressed                  bool
	reader                      storage.Reader
}
type File struct {
	source                                       storage.Reader
	size                                         int64
	Chunks                                       []Chunk
	cache                                        *bytecache.Cache
	replay                                       *bytecache.Cache
	xzChunks, xzBytes, replayBlocks, replayBytes atomic.Uint64
}

func (f *File) Size() int64 { return f.size }
func Open(source storage.Reader, maximum int64) (*File, error) {
	return OpenWithReplayCache(source, maximum, 0)
}

// OpenWithReplayCache optionally retains verified chunks in a fast-compressed
// in-memory LRU in addition to the 64 MiB decoded cache. It never decodes ahead
// or persists intermediates. replayBytes bounds retained encoded bytes, not
// temporary decoder/output buffers or concurrent callers' borrowed results.
// Zero preserves Open's original retention policy.
func OpenWithReplayCache(source storage.Reader, maximum, replayBytes int64) (*File, error) {
	if replayBytes < 0 {
		return nil, fmt.Errorf("pbzx: negative replay cache budget")
	}
	if source == nil || source.Size() < 12 || maximum < 0 {
		return nil, fmt.Errorf("pbzx: invalid source/maximum")
	}
	if maximum == 0 {
		maximum = math.MaxInt64
	}
	var h [16]byte
	if _, err := source.ReadAt(h[:12], 0); err != nil {
		return nil, err
	}
	block := binary.BigEndian.Uint64(h[4:12])
	if string(h[:4]) != "pbzx" || block == 0 || block > MaxChunk {
		return nil, fmt.Errorf("pbzx: invalid header/chunk bound")
	}
	f := &File{source: source, cache: bytecache.New(MaxChunk)}
	if replayBytes > 0 {
		f.replay = bytecache.New(replayBytes)
	}
	off := int64(12)
	for off < source.Size() {
		if len(f.Chunks) >= MaxChunks || source.Size()-off < 16 {
			return nil, fmt.Errorf("pbzx: truncated/excessive chunk headers")
		}
		if _, err := source.ReadAt(h[:], off); err != nil {
			return nil, err
		}
		expanded, packed := binary.BigEndian.Uint64(h[:8]), binary.BigEndian.Uint64(h[8:])
		off += 16
		if expanded == 0 || expanded > block || packed == 0 || packed > MaxChunk || packed > uint64(source.Size()-off) || expanded > uint64(maximum-f.size) {
			return nil, fmt.Errorf("pbzx: invalid chunk bounds")
		}
		r := io.NewSectionReader(source, off, int64(packed))
		c := Chunk{Offset: off, Length: int64(packed), Start: f.size, Size: int64(expanded), Compressed: packed != expanded, reader: r}
		if c.Compressed {
			var magic [6]byte
			if _, err := r.ReadAt(magic[:], 0); err != nil {
				return nil, err
			}
			if !bytes.Equal(magic[:], []byte{0xfd, '7', 'z', 'X', 'Z', 0}) {
				return nil, fmt.Errorf("pbzx: compressed chunk is not XZ")
			}
			decoded, err := xz.Open(r, MaxChunk)
			if err != nil {
				return nil, fmt.Errorf("pbzx: chunk %d: %w", len(f.Chunks), err)
			}
			if decoded.Size() != c.Size {
				return nil, fmt.Errorf("pbzx: chunk declared/XZ length mismatch")
			}
		}
		f.Chunks = append(f.Chunks, c)
		f.size += c.Size
		off += c.Length
		if c.Size < int64(block) && off != source.Size() {
			return nil, fmt.Errorf("pbzx: data after short final chunk")
		}
	}
	if len(f.Chunks) == 0 {
		return nil, fmt.Errorf("pbzx: no chunks")
	}
	return f, nil
}
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("pbzx: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.size {
		return 0, io.EOF
	}
	wanted := len(p)
	p = p[:min(int64(len(p)), f.size-off)]
	done := 0
	i := sort.Search(len(f.Chunks), func(i int) bool { return f.Chunks[i].Start+f.Chunks[i].Size > off })
	for len(p) > 0 {
		c := f.Chunks[i]
		skip := off - c.Start
		n := min(int64(len(p)), c.Size-skip)
		if !c.Compressed {
			if _, err := io.ReadFull(io.NewSectionReader(c.reader, skip, n), p[:n]); err != nil {
				return done, err
			}
		} else if f.replay != nil {
			read, err := f.readReplay(p[:n], i, c, skip)
			if err != nil {
				return done + read, fmt.Errorf("pbzx: chunk %d: %w", i, err)
			}
		} else {
			data, err := f.cache.Get(bytecache.Key{Index: i}, func() ([]byte, error) {
				return f.decodeChunk(c)
			})
			if err != nil {
				return done, fmt.Errorf("pbzx: chunk %d: %w", i, err)
			}
			copy(p[:n], data[skip:skip+n])
		}
		done += int(n)
		off += n
		p = p[n:]
		i++
	}
	if done != wanted {
		return done, io.EOF
	}
	return done, nil
}
