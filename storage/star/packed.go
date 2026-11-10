package star

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	"go.starlark.net/starlark"
)

const PackedChunkBytes = 64 << 10

// A bounded, concurrency-safe decoder is shared across all stores. Files retain
// neither their encoder nor a separate decoder working set. DecodeAll rejects
// output beyond the expected chunk capacity before growing its destination.
var packedDecoder = sync.OnceValues(func() (*zstd.Decoder, error) {
	return zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true),
		zstd.WithDecoderMaxWindow(PackedChunkBytes), zstd.WithDecoderMaxMemory(PackedChunkBytes), zstd.WithDecodeAllCapLimit(true))
})

// PackedFileStore snapshots bytes as independent compressed chunks in memory.
// Returned files own their chunks and shared bounded read cache, not the encoder
// or original source. A deduplicating store retains encoded chunks until the
// store is released; disable deduplication when an external LRU owns retention.
type PackedFileStore struct {
	mu     sync.Mutex
	writer *zstd.Encoder
	buffer []byte
	cache  *bytecache.Cache
	next   uint64
	chunks map[retainedChunkKey][]byte
}

type retainedChunkKey struct {
	hash [sha256.Size]byte
	raw  bool
}

func NewPackedFileStore(cacheBytes int64, deduplicate bool) (*PackedFileStore, error) {
	if cacheBytes < 0 {
		return nil, fmt.Errorf("negative packed read cache limit")
	}
	writer, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(PackedChunkBytes), zstd.WithLowerEncoderMem(true))
	if err != nil {
		return nil, err
	}
	store := &PackedFileStore{writer: writer, cache: bytecache.New(cacheBytes)}
	if deduplicate {
		store.chunks = make(map[retainedChunkKey][]byte)
	}
	return store, nil
}

type retainedChunk struct {
	data []byte
	raw  bool
}

type PackedFile struct {
	name   string
	length int64
	chunks []retainedChunk
	cache  *bytecache.Cache
	id     uint64
}

// Pack copies its input; callers may reuse their buffer immediately.
// This is storage, not authentication; callers retain format integrity policy.
func (s *PackedFileStore) Pack(name string, data []byte) (File, error) {
	if len(data) < 4096 {
		return &Bytes{Name: name, Data: bytes.Clone(data)}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	f := &PackedFile{name: name, length: int64(len(data)), cache: s.cache, id: s.next,
		chunks: make([]retainedChunk, 0, 1+(len(data)-1)/PackedChunkBytes)}
	for off := 0; off < len(data); off += PackedChunkBytes {
		part := data[off:min(off+PackedChunkBytes, len(data))]
		chunk, err := s.packChunk(part)
		if err != nil {
			return nil, err
		}
		f.chunks = append(f.chunks, chunk)
	}
	return f, nil
}

func (f *PackedFile) chunk(index int) ([]byte, error) {
	chunk := f.chunks[index]
	if chunk.raw {
		return chunk.data, nil
	}
	size := min(int64(PackedChunkBytes), f.length-int64(index)*PackedChunkBytes)
	return f.cache.Get(bytecache.Key{Source: f.id, Index: index}, func() ([]byte, error) {
		decoder, err := packedDecoder()
		if err != nil {
			return nil, err
		}
		data, err := decoder.DecodeAll(chunk.data, make([]byte, 0, int(size)))
		if err != nil {
			return nil, fmt.Errorf("retained file %q chunk %d: %w", f.name, index, err)
		}
		if len(data) != int(size) {
			return nil, fmt.Errorf("retained file %q chunk %d: decoded length %d, want %d", f.name, index, len(data), size)
		}
		return data, nil
	})
}

func (f *PackedFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative retained file offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.length {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && off < f.length {
		data, err := f.chunk(int(off / PackedChunkBytes))
		if err != nil {
			return n, err
		}
		copied := copy(p[n:], data[int(off%PackedChunkBytes):])
		n += copied
		off += int64(copied)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (*PackedFile) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("retained file is read-only")
}
func (f *PackedFile) Size() int64                              { return f.length }
func (f *PackedFile) String() string                           { return fmt.Sprintf("<file %s size=%d>", f.name, f.length) }
func (*PackedFile) Type() string                               { return "file" }
func (*PackedFile) Freeze()                                    {}
func (*PackedFile) Truth() starlark.Bool                       { return starlark.True }
func (*PackedFile) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable: file") }
func (f *PackedFile) Attr(name string) (starlark.Value, error) { return Attr(f, name), nil }
func (*PackedFile) AttrNames() []string                        { return AttrNames() }

// packChunk requires the encoder lock and copies both compressed and raw data.
func (s *PackedFileStore) packChunk(part []byte) (retainedChunk, error) {
	s.buffer = s.writer.EncodeAll(part, s.buffer[:0])
	chunk := retainedChunk{data: s.buffer}
	if len(chunk.data) >= len(part) {
		chunk.data, chunk.raw = part, true
	}
	// Carried files and unchanged regions in successive component versions
	// can share immutable encoded bytes. This index lives only while packing
	// the image; files own the shared chunks afterwards. Check byte equality
	// as well as the digest so deduplication cannot weaken content identity.
	if s.chunks == nil {
		chunk.data = bytes.Clone(chunk.data)
		return chunk, nil
	}
	key := retainedChunkKey{hash: sha256.Sum256(chunk.data), raw: chunk.raw}
	if previous, found := s.chunks[key]; found && bytes.Equal(previous, chunk.data) {
		chunk.data = previous
	} else {
		chunk.data = bytes.Clone(chunk.data)
		if s.chunks != nil {
			s.chunks[key] = chunk.data
		}
	}
	return chunk, nil
}

// Snapshot reads a bounded source sequentially with one chunk of input scratch.
// The source must remain stable for the duration of the call. Subsequent source
// writes or disposal cannot affect the returned immutable file.
func (s *PackedFileStore) Snapshot(name string, source storage.Reader, maximum int64) (File, error) {
	if source == nil || maximum < 0 {
		return nil, fmt.Errorf("invalid snapshot source or bound")
	}
	size := source.Size()
	if size < 0 || size > maximum {
		return nil, fmt.Errorf("snapshot size %d exceeds bound %d", size, maximum)
	}
	if size < 4096 {
		data := make([]byte, int(size))
		if _, err := ReadFullAt(source, data, 0); err != nil {
			return nil, err
		}
		return &Bytes{Name: name, Data: data}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	f := &PackedFile{name: name, length: size, cache: s.cache, id: s.next}
	buffer := make([]byte, PackedChunkBytes)
	for off := int64(0); off < size; {
		part := buffer[:min(int64(len(buffer)), size-off)]
		if _, err := ReadFullAt(source, part, off); err != nil {
			return nil, err
		}
		chunk, err := s.packChunk(part)
		if err != nil {
			return nil, err
		}
		f.chunks = append(f.chunks, chunk)
		off += int64(len(part))
	}
	return f, nil
}

// Deduplicates reports whether the encoder retains a chunk identity index.
func (s *PackedFileStore) Deduplicates() bool { return s.chunks != nil }

// RetainedBytes estimates encoded bytes and chunk descriptors, excluding the
// shared decoded cache. Shared chunks may be counted by more than one file.
func (f *PackedFile) RetainedBytes() int64 {
	weight := int64(128 + len(f.chunks)*32)
	for _, chunk := range f.chunks {
		weight += int64(len(chunk.data))
	}
	return weight
}

// CacheStats reports only the shared decoded read cache, not encoded snapshots.
func (s *PackedFileStore) CacheStats() bytecache.Stats { return s.cache.Stats() }
