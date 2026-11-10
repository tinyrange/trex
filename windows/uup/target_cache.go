package uup

import (
	"container/list"
	starfile "github.com/tinyrange/trex/storage/star"
)

const maximumPackedTargetCache = int64(16 << 20)

// Construction repeatedly consumes full buffers. After handoff, only verified
// reconstructed bases are retained here, compressed under a smaller LRU budget.
// The final disk-reader cache separately owns its hot random-access targets.
// All mutations are protected by the stage's canonicalMu.
type packedTargetCache struct {
	codec       *starfile.PackedFileStore
	entries     map[string]*list.Element
	lru         list.List
	used, limit int64
}
type packedTargetEntry struct {
	key    string
	file   starfile.File
	weight int64
}

func newPackedTargetCache(limit int64) *packedTargetCache {
	return &packedTargetCache{entries: make(map[string]*list.Element), limit: limit}
}
func (c *packedTargetCache) remove(key string) {
	if element := c.entries[key]; element != nil {
		c.used -= element.Value.(packedTargetEntry).weight
		c.lru.Remove(element)
		delete(c.entries, key)
	}
}
func (c *packedTargetCache) retain(key string, data []byte) {
	if element := c.entries[key]; element != nil {
		c.lru.MoveToFront(element)
		return
	}
	// An oversized decoded target was never admitted to the old cache either.
	// Avoid allocating a second large encoding merely to discard it.
	if c.limit <= 0 || int64(len(data)) > maximumCanonicalRetainedTarget {
		return
	}
	if c.codec == nil {
		codec, err := starfile.NewPackedFileStore(0, false)
		if err != nil {
			return
		} // Caching is optional; the verified bytes remain valid.
		c.codec = codec
	}
	file, err := c.codec.Pack("verified basis", data)
	if err != nil {
		return
	}
	weight := file.Size() + 128 + int64(len(key))
	if packed, ok := file.(*starfile.PackedFile); ok {
		weight = packed.RetainedBytes() + int64(len(key))
	}
	if weight > c.limit {
		return
	}
	for c.used > c.limit-weight {
		c.remove(c.lru.Back().Value.(packedTargetEntry).key)
	}
	c.entries[key] = c.lru.PushFront(packedTargetEntry{key, file, weight})
	c.used += weight
}
func (s *CumulativeStage) cachedTarget(key string) ([]byte, error) {
	s.canonicalMu.Lock()
	if data := s.canonicalCache[key]; data != nil {
		s.canonicalMu.Unlock()
		return data, nil
	}
	var file starfile.File
	if c := s.packedTargets; c != nil {
		if element := c.entries[key]; element != nil {
			c.lru.MoveToFront(element)
			file = element.Value.(packedTargetEntry).file
		}
	}
	s.canonicalMu.Unlock()
	if file == nil {
		return nil, nil
	}
	// Retain only the local immutable file while inflating. Concurrent eviction
	// or another handoff cannot invalidate this reader or repopulate old caches.
	return starfile.ReadAll(file)
}
