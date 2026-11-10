package bytecache

import "fmt"

// Lookup returns a resident or in-flight immutable buffer without starting a
// load. It allows range readers to reuse a complete resource before decoding
// a smaller prefix. An in-flight load is joined just as it is by Get.
func (c *Cache) Lookup(key Key) ([]byte, error, bool) {
	c.mu.Lock()
	entry := c.entries[key]
	if entry == nil {
		c.mu.Unlock()
		return nil, nil, false
	}
	c.hits++
	c.mu.Unlock()
	<-entry.ready
	c.mu.Lock()
	if entry.element != nil {
		c.lru.MoveToFront(entry.element)
	}
	data, err := entry.data, entry.err
	c.mu.Unlock()
	if data == nil {
		return nil, err, true
	}
	buffer, ok := data.([]byte)
	if !ok {
		return nil, fmt.Errorf("cache: key has a non-byte value"), true
	}
	return buffer, err, true
}
