package repo

import (
	"errors"
	"io"
	"math"
	"sync"
)

// Reader is a seekable immutable view of one file version. Later workspace edits
// do not change it. Its repository must remain open. No whole-file read is needed.
type Reader struct {
	mu          sync.Mutex
	r           *Repository
	entry       Entry
	pos         int64
	closed      bool
	cachedBlock int64
	cached      []byte
}

func (w *Workspace) OpenReader(p string) (*Reader, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	p, err := clean(p)
	if err != nil {
		return nil, err
	}
	if err := w.prepare(p, false); err != nil {
		return nil, err
	}
	e, ok := w.s.get(p)
	if !ok || e.Kind != "file" {
		return nil, errors.New("not a regular file")
	}
	return &Reader{r: w.r, entry: e, cachedBlock: -1}, nil
}
func (r *Reader) Size() int64 { return r.entry.Size }
func (r *Reader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, err := r.readAt(p, r.pos)
	r.pos += int64(n)
	return n, err
}
func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.readAt(p, off)
}
func (r *Reader) readAt(p []byte, off int64) (int, error) {
	r.r.mu.Lock()
	defer r.r.mu.Unlock()
	return r.readAtRepositoryLocked(p, off)
}

// readAtRepositoryLocked requires Repository.mu and either Reader.mu or an
// unshared private Reader. Repository-internal tree loading must use this path
// rather than recursively acquiring the repository mutex through readAt.
func (r *Reader) readAtRepositoryLocked(p []byte, off int64) (int, error) {
	if r.closed {
		return 0, errors.New("reader is closed")
	}
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if err := r.r.ready(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.entry.Body != "" {
		if r.cached == nil {
			b, err := r.r.borrowBody(r.entry.Body)
			if err != nil {
				return 0, err
			}
			r.cached = b
		}
		if off >= int64(len(r.cached)) {
			return 0, io.EOF
		}
		n := copy(p, r.cached[off:])
		if n < len(p) {
			return n, io.EOF
		}
		return n, nil
	}
	n := 0
	for len(p) > 0 && off < r.entry.Size {
		block := off / BlockSize
		if r.cachedBlock != block {
			data, err := r.r.get(r.entry.Blocks[block], blockKind)
			if err != nil {
				return n, err
			}
			r.cached = data
			r.cachedBlock = block
		}
		available := min(int64(len(p)), r.entry.Size-off)
		data := r.cached[off%BlockSize:]
		amount := copy(p[:available], data)
		if amount == 0 {
			return n, errors.New("invalid file block length")
		}
		p = p[amount:]
		n += amount
		off += int64(amount)
	}
	if len(p) > 0 {
		return n, io.EOF
	}
	return n, nil
}
func (r *Reader) Seek(off int64, whence int) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, errors.New("reader is closed")
	}
	var base int64
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		base = r.pos
	case io.SeekEnd:
		base = r.entry.Size
	default:
		return 0, errors.New("invalid whence")
	}
	if off < -base || off > math.MaxInt64-base {
		return 0, errors.New("invalid seek offset")
	}
	r.pos = base + off
	return r.pos, nil
}
func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.cached = nil
	return nil
}

type StorageStats struct {
	FileBytes        int64 `json:"file_bytes"`
	ContentObjects   int64 `json:"content_objects"`
	UniqueBlocks     int64 `json:"unique_blocks"`
	NativeBodies     int64 `json:"native_bodies"`
	NativeBodyBytes  int64 `json:"native_body_bytes"`
	EncodedBodyBytes int64 `json:"encoded_body_bytes"`
	MaxDeltaDepth    byte  `json:"max_delta_depth"`
	UniqueBlockBytes int64 `json:"unique_block_bytes"`
}

func (r *Repository) StorageStats() (StorageStats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return StorageStats{}, err
	}
	if err := r.flush(); err != nil {
		return StorageStats{}, err
	}
	info, err := r.f.Stat()
	if err != nil {
		return StorageStats{}, err
	}
	if r.fast != nil {
		s := r.fast.manifest.Stats
		s.FileBytes = info.Size()
		return s, nil
	}
	s := StorageStats{FileBytes: info.Size(), ContentObjects: int64(len(r.objects))}
	for _, loc := range r.objects {
		if loc.kind == bodyKind {
			s.NativeBodies++
			s.NativeBodyBytes += int64(loc.size)
			s.EncodedBodyBytes += int64(loc.stored)
			s.MaxDeltaDepth = max(s.MaxDeltaDepth, loc.depth)
		}
		if loc.kind == blockKind {
			s.UniqueBlocks++
			s.UniqueBlockBytes += int64(loc.size)
		}
	}
	return s, nil
}
