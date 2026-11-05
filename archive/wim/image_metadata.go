package wim

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	bytecache "github.com/tinyrange/trex/storage/cache"
)

// Image-directory bytes share the archive's existing bounded cache with file
// chunks, rather than pinning every decoded edition for the archive's lifetime.
// Product selection may traverse a few directories in every edition, even when
// only one edition will supply a disk. Parsed entries and security own their
// small byte fields, so evicting metadata really releases the full image buffer.
func (w *Archive) imageMetadata(image *image) ([]byte, error) {
	if image.metadata != nil {
		return image.metadata, nil
	} // Legacy and test images.
	load := func() ([]byte, error) {
		data, err := w.readResource(image.resource)
		if err != nil {
			return nil, err
		}
		if sha256.Sum256(data) != image.metadataDigest {
			return nil, fmt.Errorf("wim image %d metadata changed after validation", image.index)
		}
		return data, nil
	}
	if w.cacheStore == nil {
		return load()
	}
	return w.cacheStore.Get(bytecache.Key{Source: w.cacheSource, Kind: 3, Offset: image.resource.offset,
		Size: image.resource.size, OriginalSize: image.resource.originalSize}, load)
}

func detachWIMEntry(e *entry) {
	for i := range e.taggedItems {
		e.taggedItems[i].data = bytes.Clone(e.taggedItems[i].data)
	}
	for i := range e.extendedAttributes {
		e.extendedAttributes[i].Value = bytes.Clone(e.extendedAttributes[i].Value)
	}
}
