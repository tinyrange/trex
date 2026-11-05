package wim

import bytecache "github.com/tinyrange/trex/storage/cache"

func (w *Archive) cachedResourceChunkRange(resource wimResource, chunk wimChunk, end int) ([]byte, error) {
	const unit = 4 << 20
	prefix := min((end+unit-1)/unit*unit, chunk.outputSize)
	if w.blobCache == nil || resource.flags&wimResourceSolid == 0 || resource.compression != 3 || prefix == chunk.outputSize {
		return w.cachedResourceChunk(resource, chunk)
	}
	key := bytecache.Key{Source: w.cacheSource, Kind: 2, Offset: resource.offset, Size: resource.size, OriginalSize: resource.originalSize, Index: chunk.index}
	if data, err, ok := w.cacheStore.Lookup(key); ok {
		return data, err
	}
	key.Kind = 4
	bucket := prefix/unit - 1
	for other := bucket; other < 15; other++ {
		key.Index = chunk.index*16 + other
		if data, err, ok := w.cacheStore.Lookup(key); ok {
			return data, err
		}
	}
	// A second request extending an existing prefix proves that this chunk is
	// being traversed, not sampled once. Promote to the complete chunk rather
	// than decoding successively larger prefixes during catalog/file scans.
	for other := 0; other < bucket; other++ {
		key.Index = chunk.index*16 + other
		if _, _, ok := w.cacheStore.Lookup(key); ok {
			return w.cachedResourceChunk(resource, chunk)
		}
	}
	key.Index = chunk.index*16 + bucket
	return w.cacheStore.Get(key, func() ([]byte, error) {
		data, err := w.readChunkPrefix(resource, chunk, prefix)
		if err != nil {
			return nil, err
		}
		// A partially expanded decoder may have full-block backing capacity.
		// Charge and retain exactly the prefix, never that oversized buffer.
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	})
}
