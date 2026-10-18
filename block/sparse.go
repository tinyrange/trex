package block

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
)

// SparseBacking is caller-owned random-access storage. It must not be shared
// with another writer. Unwritten ranges are never read from it.
type SparseBacking interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
}

const SparseChunkSize int64 = 4096

// SparseOverlay keeps changed chunks in backing at their original offsets.
// The base must remain immutable. Only chunk membership and one scratch chunk
// live in memory. The caller owns backing and must keep it open until all users
// stop. This is disposable storage, not a reopenable image or snapshot format.
//
// There is no changed-data quota. The virtual disk bounds addresses, and the
// backing filesystem's available space bounds allocation. Rewrites reuse chunks;
// reverting data does not reclaim them. Any I/O failure is terminal: Done closes,
// and subsequent I/O fails
// rather than exposing a partially written chunk or silently losing changes.
type SparseOverlay struct {
	base     Device
	backing  SparseBacking
	geometry Geometry
	mu       sync.Mutex
	dirty    map[int64]struct{}
	scratch  [SparseChunkSize]byte
	failure  error
	done     chan struct{}
}

func NewSparseOverlay(base Device, backing SparseBacking) (*SparseOverlay, error) {
	if base == nil || backing == nil {
		return nil, errors.New("sparse overlay: base and backing required")
	}
	g := base.Geometry()
	if g.Size < 0 || g.LogicalBlockSize == 0 || SparseChunkSize%int64(g.LogicalBlockSize) != 0 {
		return nil, errors.New("sparse overlay: incompatible geometry")
	}
	return &SparseOverlay{base: base, backing: backing, geometry: g, dirty: make(map[int64]struct{}), done: make(chan struct{})}, nil
}
func (d *SparseOverlay) Geometry() Geometry { return d.geometry }
func (d *SparseOverlay) Capabilities() Capabilities {
	return Capabilities{Writable: true, Flush: true, Concurrent: true}
}
func (d *SparseOverlay) Done() <-chan struct{} { return d.done }
func (d *SparseOverlay) Err() error            { d.mu.Lock(); defer d.mu.Unlock(); return d.failure }
func (d *SparseOverlay) DirtyBytes() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return int64(len(d.dirty)) * SparseChunkSize
}
func (d *SparseOverlay) fail(err error) error {
	if d.failure == nil {
		d.failure = fmt.Errorf("sparse overlay: %w", err)
		close(d.done)
	}
	return d.failure
}
func (d *SparseOverlay) ReadAt(p []byte, off int64) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failure != nil {
		return 0, d.failure
	}
	if err := ValidateRange(d.geometry.Size, off, int64(len(p))); err != nil {
		return 0, err
	}
	done := 0
	for done < len(p) {
		pos := off + int64(done)
		size := min(len(p)-done, int(SparseChunkSize-pos%SparseChunkSize))
		_, dirty := d.dirty[pos/SparseChunkSize]
		// Preserve contiguous requests to the backing file or immutable base.
		// Splitting every clean read into 4 KiB calls amplifies file I/O and
		// compressed-base lookup costs without improving overlay isolation.
		for size < len(p)-done {
			_, nextDirty := d.dirty[(pos+int64(size))/SparseChunkSize]
			if nextDirty != dirty {
				break
			}
			size += min(len(p)-done-size, int(SparseChunkSize))
		}
		var source io.ReaderAt = d.base
		if dirty {
			source = d.backing
		}
		n, err := ReadFullAt(source, p[done:done+size], pos)
		done += n
		if err != nil {
			return done, d.fail(err)
		}
	}
	return done, nil
}

// changed reads only a clean chunk and compares the portion being overwritten.
func (d *SparseOverlay) changed(p []byte, off int64) (bool, error) {
	start := off - off%SparseChunkSize
	size := min(SparseChunkSize, d.geometry.Size-start)
	if _, err := ReadFullAt(d.base, d.scratch[:size], start); err != nil {
		return false, d.fail(err)
	}
	return !bytes.Equal(d.scratch[off-start:off-start+int64(len(p))], p), nil
}
func (d *SparseOverlay) WriteAt(p []byte, off int64) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failure != nil {
		return 0, d.failure
	}
	if err := ValidateRange(d.geometry.Size, off, int64(len(p))); err != nil {
		return 0, err
	}
	done := 0
	for done < len(p) {
		pos := off + int64(done)
		index := pos / SparseChunkSize
		size := min(len(p)-done, int(SparseChunkSize-pos%SparseChunkSize))
		data, at := p[done:done+size], pos
		if _, ok := d.dirty[index]; !ok {
			changed, err := d.changed(data, pos)
			if err != nil {
				return done, err
			}
			if !changed {
				done += size
				continue
			}
			start := index * SparseChunkSize
			copy(d.scratch[pos-start:], data)
			data, at = d.scratch[:min(SparseChunkSize, d.geometry.Size-start)], start
		}
		n, err := d.backing.WriteAt(data, at)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return done, d.fail(err)
		}
		d.dirty[index] = struct{}{}
		done += size
	}
	return done, nil
}
func (d *SparseOverlay) Flush() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failure != nil {
		return d.failure
	}
	if err := d.backing.Sync(); err != nil {
		return d.fail(err)
	}
	return nil
}
