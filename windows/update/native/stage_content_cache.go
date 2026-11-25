package native

import (
	"container/list"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
)

const maximumStageCacheEntry = (512 << 20) + (1 << 20)

// stageContentCache bounds compressed targets, not their decoded sizes. A
// random disk read only inflates the requested 64-KiB chunks. At most two small
// targets reconstruct concurrently; large targets retain exclusive admission.
type stageContentCache struct {
	ctx         context.Context
	disk        storage.VerifiedContentCache
	mu          sync.Mutex
	loadMu      sync.RWMutex
	smallLoads  chan struct{}
	flights     map[bytecache.Key]*stageContentFlight
	nextSource  atomic.Uint64
	codec       *retainedFileStore
	limit, used int64
	entries     map[bytecache.Key]*list.Element
	lru         list.List
	oversized   *stageContentEntry
	stats       bytecache.Stats
}
type stageContentFlight struct {
	done chan struct{}
	file starfile.File
	err  error
}

type stageContentEntry struct {
	key    bytecache.Key
	file   starfile.File
	weight int64
}

func newStageContentCache(limit int64) (*stageContentCache, error) {
	codec, err := starfile.NewPackedFileStore(16<<20, false)
	if err != nil {
		return nil, err
	}
	// The LRU, not a permanent deduplication index, owns encoded chunks.
	return &stageContentCache{codec: codec, limit: limit, entries: make(map[bytecache.Key]*list.Element), smallLoads: make(chan struct{}, 2), flights: make(map[bytecache.Key]*stageContentFlight)}, nil
}

// lookup updates recency under the short metadata lock. It never waits for
// reconstruction of another file; completed immutable files remain readable.
func (c *stageContentCache) lookup(key bytecache.Key) starfile.File {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lookupLocked(key)
}
func (c *stageContentCache) lookupLocked(key bytecache.Key) starfile.File {
	if entry := c.entries[key]; entry != nil {
		c.stats.Hits++
		c.lru.MoveToFront(entry)
		return entry.Value.(stageContentEntry).file
	}
	if entry := c.oversized; entry != nil && entry.key == key {
		c.stats.Hits++
		return entry.file
	}
	return nil
}
func (c *stageContentCache) get(r *reopenedStageReader) (file starfile.File, err error) {
	c.mu.Lock()
	if file := c.lookupLocked(r.key); file != nil {
		c.mu.Unlock()
		return file, nil
	}
	if flight := c.flights[r.key]; flight != nil {
		c.mu.Unlock()
		<-flight.done
		return flight.file, flight.err
	}
	flight := &stageContentFlight{done: make(chan struct{})}
	c.flights[r.key] = flight
	c.mu.Unlock()
	// Publish even uncached results and errors to every joined reader. Eviction
	// cannot cause a waiter to rebuild a result that is already in flight.
	defer func() {
		c.mu.Lock()
		flight.file, flight.err = file, err
		delete(c.flights, r.key)
		close(flight.done)
		c.mu.Unlock()
	}()
	c.mu.Lock()
	c.stats.Misses++
	c.mu.Unlock()
	started := time.Now()
	defer func() {
		c.mu.Lock()
		c.stats.LoadNanoseconds += uint64(time.Since(started))
		c.mu.Unlock()
	}()
	var release func()
	defer func() {
		if release != nil {
			release()
		}
	}()
	var sourceData []byte
	var sourceError error
	load := func() ([]byte, error) {
		if release != nil {
			return sourceData, sourceError
		}
		// A verified disk hit does not reconstruct content. Admit only an
		// actual cold load, and hold its slot until its working bytes have
		// been packed or published.
		if r.size < 8<<20 {
			c.smallLoads <- struct{}{}
			c.loadMu.RLock()
			release = func() { c.loadMu.RUnlock(); <-c.smallLoads }
		} else {
			c.loadMu.Lock()
			release = c.loadMu.Unlock
		}
		sourceData, sourceError = loadStageContent(r)
		return sourceData, sourceError
	}
	var packed starfile.File
	var diskIndexBytes int64
	if c.disk != nil && r.cacheOnDisk && r.expectedSHA256 != nil {
		disk, diskErr := c.disk.GetOrBuildContent(c.ctx, *r.expectedSHA256, r.size, load)
		if sourceError != nil {
			return nil, sourceError
		}
		if diskErr == nil {
			packed = starfile.NewReader("verified staged content", disk)
			// The disk reader keeps its offset/digest index in memory.
			diskIndexBytes = 128 + 64*storage.CeilDiv(r.size, starfile.PackedChunkBytes)
		}
	}
	if packed == nil {
		data, err := load()
		if err != nil {
			return nil, err
		}
		packed, err = c.codec.Pack("staged content", data)
		if err != nil {
			return nil, err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.Loads++
	c.stats.LoadedBytes += uint64(r.size)
	weight := packed.Size() + 128
	if diskIndexBytes != 0 {
		weight = diskIndexBytes
	} else if chunks, ok := packed.(*retainedFile); ok {
		weight = chunks.RetainedBytes()
	}
	// Decoded target size, not just compressed weight, selects the large slot:
	// a highly compressible target can still take seconds to reconstruct.
	// Retain one oversized target separately from the ordinary LRU. Tiny DLL
	// reads must not evict a large target between its paging/scanning requests:
	// rebuilding it repeatedly can starve queued guest registry reads even when
	// every backing operation eventually succeeds. Both sets remain bounded.
	if c.limit > 0 && diskIndexBytes == 0 && (r.size > c.limit || weight > c.limit) && weight <= maximumStageCacheEntry {
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
