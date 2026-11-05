package native

import (
	"github.com/tinyrange/trex/archive/cab"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
)

// This cache exists only while reading one composition catalog. Uncached CAB
// entries each decode their entire solid folder; visiting sibling CompDBs can
// otherwise decompress the same aggregated metadata repeatedly. One shared
// bound covers every nested archive, with distinct source IDs to prevent folder
// collisions. Parsed databases own no CAB readers or cache references.
const maximumCompositionCache = int64(128 << 20)

type compositionCabinets struct {
	cache *bytecache.Cache
	next  uint64
}

func newCompositionCabinets() *compositionCabinets {
	return &compositionCabinets{cache: bytecache.New(maximumCompositionCache)}
}

func (c *compositionCabinets) open(file storage.Reader) (*cab.Archive, error) {
	c.next++
	return cab.OpenWithCache(file, true, c.cache, c.next)
}
