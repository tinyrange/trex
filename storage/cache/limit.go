package bytecache

// SetLimit changes the retained-byte budget and immediately evicts least-recently
// used completed values until it is met. Negative limits mean zero, as in New.
// Existing readers remain valid. In-flight loads keep their single-flight
// identity and use the new budget when they complete. Caller-held values and
// loader working memory are not included in this budget.
func (c *Cache) SetLimit(maxBytes int64) {
	if c == nil {
		return
	}
	if maxBytes < 0 {
		maxBytes = 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxBytes = maxBytes
	c.evictLocked()
}

func (c *Cache) evictLocked() {
	for c.bytes > c.maxBytes {
		oldestElement := c.lru.Back()
		if oldestElement == nil {
			break
		}
		oldest := oldestElement.Value.(*cacheEntry)
		c.lru.Remove(oldestElement)
		oldest.element = nil
		delete(c.entries, oldest.key)
		c.bytes -= oldest.weight
		c.evictions++
	}
}
