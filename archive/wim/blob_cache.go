package wim

import bytecache "github.com/tinyrange/trex/storage/cache"

// Solid ESD chunks can be 64 MiB even when the requested file is only a few
// KiB. Keep the actual small file working set independently of scratch chunks,
// so paging through another file cannot evict the first file's useful bytes.
// All three tiers share the caller's original bound; none is persisted.
func (w *Archive) configureSolidBlobCache(maximum int64) {
	if maximum < 192<<20 {
		return
	}
	largeSolid := false
	sources := map[*Archive]bool{w: true}
	for _, indexed := range w.byHash {
		location := w.expandIndexed(indexed)
		if location.archive == nil {
			continue
		}
		sources[location.archive] = true
		r := location.resource
		if r.flags&wimResourceSolid != 0 && r.compression == 3 && r.chunkSize >= 8<<20 {
			largeSolid = true
		}
	}
	if !largeSolid {
		return
	}
	chunks := bytecache.New(maximum / 8)
	hot := bytecache.New(maximum / 24)
	blobs := bytecache.New(maximum - maximum/8 - maximum/24)
	for source := range sources {
		source.cacheStore = chunks
		source.blobCache = blobs
		source.blobHotCache = hot
	}
}
