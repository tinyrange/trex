// Package bytecache provides a concurrency-safe, size-bounded byte LRU with
// single-flight loading. Keys describe format resources without depending on
// host paths or processes.
package bytecache

import (
	"container/list"
	"sync"
)

// A single-folder cabinet, notably the 315 MiB Windows XP driver.cab, must be
// admissible or every small read repeats decompression of the entire folder.
// The shared LRU remains bounded and WIM resources continue to cache by chunk.
const DefaultBytes = 384 << 20

type Key struct {
	Source       uint64
	Kind         uint8
	Offset       int64
	Size         int64
	OriginalSize int64
	Index        int
}

type cacheEntry struct {
	key     Key
	ready   chan struct{}
	data    []byte
	err     error
	element *list.Element
}

type Stats struct {
	Hits        uint64
	Misses      uint64
	Evictions   uint64
	Loads       uint64
	LoadedBytes uint64
	Bytes       int64
	PeakBytes   int64
	Entries     int
}

type Cache struct {
	mu        sync.Mutex
	maxBytes  int64
	bytes     int64
	entries   map[Key]*cacheEntry
	lru       list.List
	hits      uint64
	misses    uint64
	evictions uint64
	loads     uint64
	loaded    uint64
	peakBytes int64
	onLoad    func(uint64)
}

func New(maxBytes int64) *Cache {
	return NewObserved(maxBytes, nil)
}

// NewObserved creates a cache and reports each successfully loaded byte count.
func NewObserved(maxBytes int64, onLoad func(uint64)) *Cache {
	if maxBytes < 0 {
		maxBytes = 0
	}
	return &Cache{
		maxBytes: maxBytes,
		entries:  make(map[Key]*cacheEntry),
		onLoad:   onLoad,
	}
}

func (c *Cache) Get(key Key, load func() ([]byte, error)) ([]byte, error) {
	c.mu.Lock()
	if entry := c.entries[key]; entry != nil {
		c.hits++
		ready := entry.ready
		c.mu.Unlock()
		<-ready
		c.mu.Lock()
		if entry.element != nil {
			c.lru.MoveToFront(entry.element)
		}
		data, err := entry.data, entry.err
		c.mu.Unlock()
		return data, err
	}
	c.misses++
	entry := &cacheEntry{key: key, ready: make(chan struct{})}
	c.entries[key] = entry
	c.mu.Unlock()

	data, err := load()

	c.mu.Lock()
	if err == nil {
		c.loads++
		c.loaded += uint64(len(data))
		if c.onLoad != nil {
			c.onLoad(uint64(len(data)))
		}
	}
	entry.data, entry.err = data, err
	if err == nil && int64(len(data)) <= c.maxBytes {
		entry.element = c.lru.PushFront(entry)
		c.bytes += int64(len(data))
		if c.bytes > c.peakBytes {
			c.peakBytes = c.bytes
		}
	} else {
		delete(c.entries, key)
	}
	close(entry.ready)
	for c.bytes > c.maxBytes {
		oldestElement := c.lru.Back()
		if oldestElement == nil {
			break
		}
		oldest := oldestElement.Value.(*cacheEntry)
		c.lru.Remove(oldestElement)
		oldest.element = nil
		delete(c.entries, oldest.key)
		c.bytes -= int64(len(oldest.data))
		c.evictions++
	}
	c.mu.Unlock()
	return data, err
}

func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{
		Hits:        c.hits,
		Misses:      c.misses,
		Evictions:   c.evictions,
		Loads:       c.loads,
		LoadedBytes: c.loaded,
		Bytes:       c.bytes,
		PeakBytes:   c.peakBytes,
		Entries:     len(c.entries),
	}
}
