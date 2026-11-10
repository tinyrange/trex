package bytecache

// Clear evicts completed entries without invalidating bytes already returned
// to callers. In-flight loads retain their single-flight identity and may
// populate the cache after Clear returns. It is safe alongside Get and Stats.
func (c *Cache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if entry.element == nil {
			continue
		}
		c.lru.Remove(entry.element)
		entry.element = nil
		delete(c.entries, key)
		c.bytes -= entry.weight
		c.evictions++
	}
}
