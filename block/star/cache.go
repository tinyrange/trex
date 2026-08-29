package star

import (
	"container/list"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"go.starlark.net/starlark"
)

const (
	defaultBlockCacheSize  = 32 << 20
	defaultBlockCacheChunk = 64 << 10
)

const (
	DefaultCacheSize  = defaultBlockCacheSize
	DefaultCacheChunk = defaultBlockCacheChunk
)

type blockCacheEntry struct {
	index   int64
	data    []byte
	err     error
	ready   chan struct{}
	element *list.Element
}

type cachedBlockDevice struct {
	base      BlockDevice
	maxBytes  int64
	chunkSize int64

	mu      sync.Mutex
	entries map[int64]*blockCacheEntry
	lru     list.List
	bytes   int64
	hits    atomic.Uint64
	misses  atomic.Uint64
	waits   atomic.Uint64
	evicts  atomic.Uint64
}

type CachedDevice = cachedBlockDevice

func NewCachedDevice(base BlockDevice, maxBytes, chunkSize int64) (*CachedDevice, error) {
	return newCachedBlockDevice(base, maxBytes, chunkSize)
}

func (d *cachedBlockDevice) Misses() uint64 { return d.misses.Load() }

func newCachedBlockDevice(base BlockDevice, maxBytes, chunkSize int64) (*cachedBlockDevice, error) {
	if base.Capabilities().Writable {
		return nil, fmt.Errorf("block.cache: base must be read-only; place the cache below a writable overlay")
	}
	if maxBytes <= 0 || chunkSize <= 0 {
		return nil, fmt.Errorf("block.cache: max_bytes and chunk_size must be positive")
	}
	if chunkSize > maxBytes {
		return nil, fmt.Errorf("block.cache: chunk_size exceeds max_bytes")
	}
	if logical := int64(base.Geometry().LogicalBlockSize); chunkSize%logical != 0 {
		return nil, fmt.Errorf("block.cache: chunk_size must be a multiple of the logical block size")
	}
	return &cachedBlockDevice{
		base:      base,
		maxBytes:  maxBytes,
		chunkSize: chunkSize,
		entries:   make(map[int64]*blockCacheEntry),
	}, nil
}

func blockCacheBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maxBytes := int64(defaultBlockCacheSize)
	chunkSize := int64(defaultBlockCacheChunk)
	if err := starlark.UnpackArgs("cache", args, kwargs,
		"base", &value,
		"max_bytes?", &maxBytes,
		"chunk_size?", &chunkSize,
	); err != nil {
		return nil, err
	}
	base, err := AsDevice(value)
	if err != nil {
		return nil, fmt.Errorf("cache: base: %w", err)
	}
	cache, err := newCachedBlockDevice(base, maxBytes, chunkSize)
	if err != nil {
		return nil, err
	}
	return NewValue("cache", cache), nil
}

func (d *cachedBlockDevice) Geometry() BlockGeometry { return d.base.Geometry() }

func (d *cachedBlockDevice) Capabilities() BlockCapabilities {
	capabilities := d.base.Capabilities()
	capabilities.Writable = false
	capabilities.Flush = false
	capabilities.Zero = false
	capabilities.Trim = false
	capabilities.Durable = false
	capabilities.Concurrent = true
	capabilities.Prefetch = true
	if _, ok := d.base.(blockDeviceExtenter); !ok {
		capabilities.Extents = false
	}
	return capabilities
}

func (d *cachedBlockDevice) Prefetch(off, length int64) error {
	if err := validateBlockRange(d.Geometry().Size, off, length); err != nil {
		return err
	}
	if length == 0 {
		return nil
	}
	first := off / d.chunkSize
	last := (off + length - 1) / d.chunkSize
	for index := first; index <= last; index++ {
		if _, err := d.chunk(index); err != nil {
			return err
		}
	}
	return nil
}

func (d *cachedBlockDevice) Extents(off, length int64) ([]BlockExtent, error) {
	extenter, ok := d.base.(blockDeviceExtenter)
	if !ok || !d.base.Capabilities().Extents {
		return nil, ErrBlockUnsupported
	}
	return extenter.Extents(off, length)
}

func (d *cachedBlockDevice) ReadAt(p []byte, off int64) (int, error) {
	if err := validateBlockRange(d.Geometry().Size, off, int64(len(p))); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	done := 0
	for done < len(p) {
		absolute := off + int64(done)
		index := absolute / d.chunkSize
		within := absolute % d.chunkSize
		data, err := d.chunk(index)
		if err != nil {
			return done, err
		}
		available := int64(len(data)) - within
		if available <= 0 {
			return done, io.ErrUnexpectedEOF
		}
		count := int64(len(p) - done)
		if count > available {
			count = available
		}
		copy(p[done:done+int(count)], data[within:within+count])
		done += int(count)
	}
	return done, nil
}

func (d *cachedBlockDevice) chunk(index int64) ([]byte, error) {
	d.mu.Lock()
	if entry, ok := d.entries[index]; ok {
		if entry.ready != nil {
			ready := entry.ready
			d.waits.Add(1)
			d.mu.Unlock()
			<-ready
			d.mu.Lock()
		}
		if entry.element != nil {
			d.lru.MoveToFront(entry.element)
		}
		data, err := entry.data, entry.err
		d.hits.Add(1)
		d.mu.Unlock()
		return data, err
	}
	entry := &blockCacheEntry{index: index, ready: make(chan struct{})}
	d.entries[index] = entry
	d.misses.Add(1)
	d.mu.Unlock()

	off := index * d.chunkSize
	length := d.chunkSize
	if remaining := d.Geometry().Size - off; remaining < length {
		length = remaining
	}
	if length <= 0 {
		entry.err = io.EOF
	} else {
		entry.data = make([]byte, length)
		_, entry.err = d.base.ReadAt(entry.data, off)
	}

	d.mu.Lock()
	ready := entry.ready
	entry.ready = nil
	if entry.err == nil {
		entry.element = d.lru.PushFront(entry)
		d.bytes += int64(len(entry.data))
		d.evictLocked()
	} else {
		delete(d.entries, index)
	}
	close(ready)
	data, err := entry.data, entry.err
	d.mu.Unlock()
	return data, err
}

func (d *cachedBlockDevice) evictLocked() {
	for d.bytes > d.maxBytes {
		element := d.lru.Back()
		if element == nil {
			return
		}
		entry := element.Value.(*blockCacheEntry)
		d.lru.Remove(element)
		delete(d.entries, entry.index)
		d.bytes -= int64(len(entry.data))
		d.evicts.Add(1)
	}
}

func (d *cachedBlockDevice) Stats() starlark.StringDict {
	d.mu.Lock()
	bytes, entries := d.bytes, len(d.entries)
	d.mu.Unlock()
	return starlark.StringDict{
		"bytes":     starlark.MakeInt64(bytes),
		"entries":   starlark.MakeInt(entries),
		"evictions": starlark.MakeUint64(d.evicts.Load()),
		"hits":      starlark.MakeUint64(d.hits.Load()),
		"max_bytes": starlark.MakeInt64(d.maxBytes),
		"misses":    starlark.MakeUint64(d.misses.Load()),
		"waits":     starlark.MakeUint64(d.waits.Load()),
	}
}
