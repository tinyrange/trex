package cab

// ReleaseReadCaches drops decoded folders without invalidating readers.
// Subsequent large LZX reads use source-backed checkpoints; Quantum reads retain
// packed chunks instead of expanded folders. MSZIP dictionary checkpoints remain
// available; uncached entry ownership is unchanged.
// In-flight loads can repopulate the shared cache after this call returns.
func (c *Archive) ReleaseReadCaches() {
	if c != nil {
		c.compactCache.Store(true)
		c.cacheStore.Clear()
		if c.lzxCheckpointBytes > 0 {
			for i := range c.indexedLZXFolders() {
				x := &c.lzxFolders[i]
				x.mu.Lock()
				if x.reader != nil {
					x.reader.ReleaseReadCache()
				}
				x.mu.Unlock()
			}
		}
	}
}
