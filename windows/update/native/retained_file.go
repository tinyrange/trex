package native

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"

	bytecache "github.com/tinyrange/trex/storage/cache"
	starvalue "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const retainedChunkBytes = 64 << 10
const maximumRetainedReadCache = 64 << 20

// Store verified bytes as immutable independent compressed chunks without
// host intermediates. Canonical source resources can own these readers; the
// servicing-output working set is bounded separately by verifiedFileCache.
// This is private media policy using portable file/cache abstractions.
type retainedFileStore struct {
	mu     sync.Mutex
	writer *flate.Writer
	buffer bytes.Buffer
	cache  *bytecache.Cache
	next   uint64
	chunks map[retainedChunkKey][]byte
}

type retainedChunkKey struct {
	hash [sha256.Size]byte
	raw  bool
}

func newRetainedFileStore() (*retainedFileStore, error) {
	writer, err := flate.NewWriter(io.Discard, flate.BestSpeed)
	if err != nil {
		return nil, err
	}
	return &retainedFileStore{writer: writer, cache: bytecache.New(maximumRetainedReadCache), chunks: make(map[retainedChunkKey][]byte)}, nil
}

type retainedChunk struct {
	data []byte
	raw  bool
}

type retainedFile struct {
	name   string
	length int64
	chunks []retainedChunk
	cache  *bytecache.Cache
	id     uint64
}

// pack copies its input; cabinet visitors may reuse their buffer immediately.
// Callers must perform the original format's mandatory hash checks first.
func (s *retainedFileStore) pack(name string, data []byte) (starvalue.File, error) {
	if len(data) < 4096 {
		return &starvalue.Bytes{Name: name, Data: bytes.Clone(data)}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	f := &retainedFile{name: name, length: int64(len(data)), cache: s.cache, id: s.next}
	for off := 0; off < len(data); off += retainedChunkBytes {
		part := data[off:min(off+retainedChunkBytes, len(data))]
		s.buffer.Reset()
		s.writer.Reset(&s.buffer)
		if _, err := s.writer.Write(part); err != nil {
			return nil, err
		}
		if err := s.writer.Close(); err != nil {
			return nil, err
		}
		chunk := retainedChunk{data: s.buffer.Bytes()}
		if len(chunk.data) >= len(part) {
			chunk.data, chunk.raw = part, true
		}
		// Carried files and unchanged regions in successive component versions
		// can share immutable encoded bytes. This index lives only while packing
		// the image; files own the shared chunks afterwards. Check byte equality
		// as well as the digest so deduplication cannot weaken content identity.
		key := retainedChunkKey{hash: sha256.Sum256(chunk.data), raw: chunk.raw}
		if previous, found := s.chunks[key]; found && bytes.Equal(previous, chunk.data) {
			chunk.data = previous
		} else {
			chunk.data = bytes.Clone(chunk.data)
			if s.chunks != nil {
				s.chunks[key] = chunk.data
			}
		}
		f.chunks = append(f.chunks, chunk)
	}
	return f, nil
}

func (f *retainedFile) chunk(index int) ([]byte, error) {
	chunk := f.chunks[index]
	if chunk.raw {
		return chunk.data, nil
	}
	size := min(int64(retainedChunkBytes), f.length-int64(index)*retainedChunkBytes)
	return f.cache.Get(bytecache.Key{Source: f.id, Index: index}, func() ([]byte, error) {
		reader := flate.NewReader(bytes.NewReader(chunk.data))
		defer reader.Close()
		data := make([]byte, int(size))
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, fmt.Errorf("retained file %q chunk %d: %w", f.name, index, err)
		}
		var extra [1]byte
		if n, err := reader.Read(extra[:]); n != 0 || err != io.EOF {
			return nil, fmt.Errorf("retained file %q chunk %d exceeds decoded extent or has invalid end: %v", f.name, index, err)
		}
		return data, nil
	})
}

func (f *retainedFile) ReadAt(p []byte, off int64) (int, error) {
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
		data, err := f.chunk(int(off / retainedChunkBytes))
		if err != nil {
			return n, err
		}
		copied := copy(p[n:], data[int(off%retainedChunkBytes):])
		n += copied
		off += int64(copied)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (*retainedFile) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("retained file is read-only")
}
func (f *retainedFile) Size() int64                              { return f.length }
func (f *retainedFile) String() string                           { return fmt.Sprintf("<file %s size=%d>", f.name, f.length) }
func (*retainedFile) Type() string                               { return "file" }
func (*retainedFile) Freeze()                                    {}
func (*retainedFile) Truth() starlark.Bool                       { return starlark.True }
func (*retainedFile) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable: file") }
func (f *retainedFile) Attr(name string) (starlark.Value, error) { return starvalue.Attr(f, name), nil }
func (*retainedFile) AttrNames() []string                        { return starvalue.AttrNames() }
