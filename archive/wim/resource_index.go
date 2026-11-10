package wim

import (
	"encoding/binary"
	"github.com/tinyrange/trex/storage"
	"sync"
)

// Solid resources contain many independently hashed files. Retain the physical
// reader and compression descriptor once, rather than copying them into every
// hash-table bucket. A binary digest key also avoids a separately allocated
// string for each hash. Published indexes are read-only, just as before.
type wimResourceBacking struct {
	archive    *Archive
	external   storage.Reader
	resource   wimResource
	readerOnce sync.Once
	reader     storage.Reader
}

type compactResourceLocation struct {
	*wimResourceBacking
	blobOffset int64
	blobSize   int64
	refCount   uint32
	lookupPart uint16
}

func (l compactResourceLocation) expand() wimResourceLocation {
	return wimResourceLocation{archive: l.archive, external: l.external, resource: l.resource,
		blobOffset: l.blobOffset, blobSize: l.blobSize, refCount: l.refCount, lookupPart: l.lookupPart}
}

// Hash buckets contain no pointers: the GC need only scan the much smaller
// table of physical resources, not every solid member's hash and extent.
// Encode the fixed-width fields without Go struct alignment padding. Large
// solid archives retain hundreds of thousands of these values in hash buckets;
// keeping all 26 bytes packed reduces both bucket size and allocator rounding.
// This is an internal memory representation, not a serialized WIM structure.
type indexedResourceLocation [26]byte

func indexResourceLocation(location compactResourceLocation, backing uint32) (out indexedResourceLocation) {
	binary.LittleEndian.PutUint64(out[0:8], uint64(location.blobOffset))
	binary.LittleEndian.PutUint64(out[8:16], uint64(location.blobSize))
	binary.LittleEndian.PutUint32(out[16:20], backing)
	binary.LittleEndian.PutUint32(out[20:24], location.refCount)
	binary.LittleEndian.PutUint16(out[24:26], location.lookupPart)
	return
}

func (l indexedResourceLocation) blobSize() int64 {
	return int64(binary.LittleEndian.Uint64(l[8:16]))
}

func (l indexedResourceLocation) backing() uint32 {
	return binary.LittleEndian.Uint32(l[16:20])
}

func (l indexedResourceLocation) remapBacking(base uint32) indexedResourceLocation {
	binary.LittleEndian.PutUint32(l[16:20], l.backing()+base)
	return l
}

func (w *Archive) expandIndexed(l indexedResourceLocation) compactResourceLocation {
	return compactResourceLocation{w.resourceBackings[l.backing()],
		int64(binary.LittleEndian.Uint64(l[0:8])), l.blobSize(),
		binary.LittleEndian.Uint32(l[20:24]), binary.LittleEndian.Uint16(l[24:26])}
}

func (w *Archive) lookupResource(hash [20]byte) (wimResourceLocation, bool) {
	compact, ok := w.byHash[hash]
	if !ok {
		return wimResourceLocation{}, false
	}
	return w.expandIndexed(compact).expand(), true
}

func (w *Archive) addResourceLocation(hash string, location wimResourceLocation) {
	// Internal callers use exact SHA-1 bytes, never textual digests.
	if len(hash) != 20 {
		panic("wim: invalid internal resource digest")
	}
	var key [20]byte
	copy(key[:], hash)
	backing := w.lastResource
	// Lookup entries belonging to a solid run are consecutive. External
	// readers need not be comparable and are deliberately never interned.
	if backing == nil || location.external != nil || backing.external != nil ||
		backing.archive != location.archive || backing.resource != location.resource {
		backing = w.newResourceBacking(location)
		w.lastResource = backing
	}
	w.addCompactLocation(key, compactResourceLocation{backing, location.blobOffset,
		location.blobSize, location.refCount, location.lookupPart})
}

// Reference imports share immutable backing descriptors directly. This remains
// valid after their private hash indexes are released.
func (w *Archive) addCompactLocation(hash [20]byte, location compactResourceLocation) {
	var backing uint32
	if n := len(w.resourceBackings); n > 0 && w.resourceBackings[n-1] == location.wimResourceBacking {
		backing = uint32(n - 1)
	} else {
		if uint64(len(w.resourceBackings)) >= 1<<32 {
			panic("wim: too many resource backings")
		}
		backing = uint32(len(w.resourceBackings))
		w.resourceBackings = append(w.resourceBackings, location.wimResourceBacking)
	}
	w.addIndexedLocation(hash, indexResourceLocation(location, backing))
}

func (w *Archive) addIndexedLocation(hash [20]byte, location indexedResourceLocation) {
	if w.byHash == nil {
		w.byHash = make(map[[20]byte]indexedResourceLocation)
	}
	if previous, ok := w.byHash[hash]; ok {
		if w.locationsByHash == nil {
			w.locationsByHash = make(map[string][]wimResourceLocation)
		}
		key := string(hash[:])
		locations := w.locationsByHash[key]
		if len(locations) == 0 {
			locations = append(locations, w.expandIndexed(previous).expand())
		}
		w.locationsByHash[key] = append(locations, w.expandIndexed(location).expand())
	}
	w.byHash[hash] = location
}

func (w *Archive) resourceLocations(hash string) []wimResourceLocation {
	if len(hash) != 20 {
		return nil
	}
	if locations := w.locationsByHash[hash]; len(locations) != 0 {
		return locations
	}
	var key [20]byte
	copy(key[:], hash)
	if location, ok := w.lookupResource(key); ok {
		return []wimResourceLocation{location}
	}
	return nil
}

// Chunk-table state belongs to the physical resource, not each solid member.
// Names are diagnostic only; no host paths or mutable input are introduced.
func (b *wimResourceBacking) contentReader() storage.Reader {
	b.readerOnce.Do(func() {
		if b.external != nil {
			b.reader = b.external
		} else {
			b.reader = newResourceFile("shared content", b.archive, b.resource)
		}
	})
	return b.reader
}

func (b *wimResourceBacking) Size() int64 {
	if b.external != nil {
		return b.external.Size()
	}
	if b.resource.originalSize != 0 {
		return b.resource.originalSize
	}
	return b.resource.size
}
func (b *wimResourceBacking) ReadAt(p []byte, off int64) (int, error) {
	return b.contentReader().ReadAt(p, off)
}
