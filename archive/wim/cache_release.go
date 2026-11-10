package wim

// ReleaseReadCaches drops reconstructible metadata indexes and decoded bytes.
// File readers and resource identities remain valid. Sources must remain
// immutable, as for every cached archive read. Concurrent loads can repopulate
// caches; this is a lifetime boundary, not a persistent zero-cache policy.
func (w *Archive) ReleaseReadCaches() {
	if w == nil {
		return
	}
	w.directoryMu.Lock()
	for i := range w.images {
		image := &w.images[i]
		// Hand-built directory-only images have no rereadable metadata source.
		if len(image.metadata) == 0 && image.resource.originalSize == 0 {
			continue
		}
		image.compactMetadata = true
		image.dirs = make(map[string][]entry)
		image.byPath = map[string]*entry{wimPathKey(image.root.path): &image.root}
	}
	w.directoryMu.Unlock()
	w.cacheStore.Clear()
	w.blobCache.Clear()
	w.blobHotCache.Clear()
}

// SetChunkCacheLimit changes the decoded resource-chunk cache budget. Archives
// sharing this cache (including reference archives) share the new limit. This
// does not resize the independent solid-blob or hot-file caches, nor change
// resource identities or invalidate existing readers. It is safe during reads.
func (w *Archive) SetChunkCacheLimit(maxBytes int64) {
	if w != nil {
		w.cacheStore.SetLimit(maxBytes)
	}
}
