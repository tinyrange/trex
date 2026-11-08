package native

import (
	"container/list"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"time"

	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
)

const maximumStageCacheEntry = (512 << 20) + (1 << 20)

// stageContentCache bounds compressed targets, not their decoded sizes. A
// random disk read only inflates the requested 64-KiB chunks. Serialize misses
// so concurrent disk requests cannot each allocate a full delta working set.
type stageContentCache struct {
	mu          sync.Mutex
	codec       *retainedFileStore
	limit, used int64
	entries     map[bytecache.Key]*list.Element
	lru         list.List
	oversized   *stageContentEntry
	stats       bytecache.Stats
}
type stageContentEntry struct {
	key    bytecache.Key
	file   starfile.File
	weight int64
}

func newStageContentCache(limit int64) (*stageContentCache, error) {
	codec, err := newRetainedFileStore()
	if err != nil {
		return nil, err
	}
	// The LRU, not a permanent deduplication index, owns encoded chunks.
	codec.chunks = nil
	return &stageContentCache{codec: codec, limit: limit, entries: make(map[bytecache.Key]*list.Element)}, nil
}
func (c *stageContentCache) get(r *reopenedStageReader) (starfile.File, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry := c.entries[r.key]; entry != nil {
		c.stats.Hits++
		c.lru.MoveToFront(entry)
		return entry.Value.(stageContentEntry).file, nil
	}
	if entry := c.oversized; entry != nil && entry.key == r.key {
		c.stats.Hits++
		return entry.file, nil
	}
	c.stats.Misses++
	started := time.Now()
	defer func() { c.stats.LoadNanoseconds += uint64(time.Since(started)) }()
	data, err := loadStageContent(r)
	if err != nil {
		return nil, err
	}
	packed, err := c.codec.pack("staged content", data)
	if err != nil {
		return nil, err
	}
	c.stats.Loads++
	c.stats.LoadedBytes += uint64(len(data))
	weight := packed.Size() + 128
	if chunks, ok := packed.(*retainedFile); ok {
		weight = 128 + int64(len(chunks.chunks))*32
		for _, chunk := range chunks.chunks {
			weight += int64(len(chunk.data))
		}
	}
	// Retain one oversized target separately from the ordinary LRU. Tiny DLL
	// reads must not evict a large target between its paging/scanning requests:
	// rebuilding it repeatedly can starve queued guest registry reads even when
	// every backing operation eventually succeeds. Both sets remain bounded.
	if c.limit > 0 && weight > c.limit && weight <= maximumStageCacheEntry {
		if c.oversized != nil {
			c.stats.Evictions++
		}
		c.oversized = &stageContentEntry{r.key, packed, weight}
	} else if weight <= c.limit {
		for c.used > c.limit-weight {
			oldest := c.lru.Back()
			old := oldest.Value.(stageContentEntry)
			delete(c.entries, old.key)
			c.used -= old.weight
			c.lru.Remove(oldest)
			c.stats.Evictions++
		}
		c.entries[r.key] = c.lru.PushFront(stageContentEntry{r.key, packed, weight})
		c.used += weight
	}
	retained := c.used
	if c.oversized != nil {
		retained += c.oversized.weight
	}
	if retained > c.stats.PeakBytes {
		c.stats.PeakBytes = retained
	}
	return packed, nil
}
func (c *stageContentCache) Stats() bytecache.Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Bytes = c.used
	s.Entries = len(c.entries)
	if c.oversized != nil {
		s.Bytes += c.oversized.weight
		s.Entries++
	}
	return s
}

func loadStageContent(r *reopenedStageReader) ([]byte, error) {
	f, err := r.open()
	if err != nil {
		return nil, err
	}
	if f.Size() != r.size || r.size < 0 || r.size > 512<<20 {
		return nil, fmt.Errorf("invalid or changed staged file length")
	}
	var data []byte
	if decoded, ok := f.(*starfile.Bytes); ok {
		data = decoded.Data
	} else {
		data = make([]byte, r.size)
		if _, err = io.ReadFull(io.NewSectionReader(f, 0, r.size), data); err != nil {
			return nil, err
		}
	}
	if int64(len(data)) != r.size {
		return nil, fmt.Errorf("invalid staged buffer length")
	}
	if r.expectedSHA256 != nil && sha256.Sum256(data) != *r.expectedSHA256 {
		return nil, fmt.Errorf("staged file content identity changed")
	}
	return data, nil
}
