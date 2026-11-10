package wim

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
)

// After a construction cache handoff, namespace misses must not pin an entire
// expanded edition again. Reload and verify exactly as for imageMetadata, then
// charge packed chunks to the same archive cache. The directory scan's bounded
// buffer is the only decoded reuse; the packed file has no persistent cache.
func (w *Archive) packedImageMetadata(image *image) (starfile.File, error) {
	load := func() (any, int64, error) {
		data, err := w.readResource(image.resource)
		if err != nil {
			return nil, 0, err
		}
		if sha256.Sum256(data) != image.metadataDigest {
			return nil, 0, fmt.Errorf("wim image %d metadata changed after validation", image.index)
		}
		store, err := starfile.NewPackedFileStore(0, false)
		if err != nil {
			return nil, 0, err
		}
		file, err := store.Pack("WIM directory metadata", data)
		if err != nil {
			return nil, 0, err
		}
		weight := file.Size() + 128
		if packed, ok := file.(*starfile.PackedFile); ok {
			weight = packed.RetainedBytes()
		}
		return file, weight, nil
	}
	var value any
	var err error
	if w.cacheStore == nil {
		value, _, err = load()
	} else {
		value, err = w.cacheStore.GetValue(bytecache.Key{Source: w.cacheSource, Kind: 6, Offset: image.resource.offset, Size: image.resource.size, OriginalSize: image.resource.originalSize}, load)
	}
	if err != nil {
		return nil, err
	}
	return value.(starfile.File), nil
}

func (w *Archive) readPackedDirectory(image *image, dir entry) ([]entry, error) {
	file, err := w.packedImageMetadata(image)
	if err != nil {
		return nil, err
	}
	if dir.subdirOff > uint64(file.Size()) {
		return nil, nil
	}
	remaining := file.Size() - int64(dir.subdirOff)
	reader := bufio.NewReaderSize(io.NewSectionReader(file, int64(dir.subdirOff), remaining), starfile.PackedChunkBytes)
	var entries []entry
	var header [8]byte
	var record []byte
	for remaining >= 8 {
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return nil, err
		}
		length := binary.LittleEndian.Uint64(header[:])
		// Match the ordinary metadata parser's terminating/invalid extent
		// policy without converting an untrusted length to int first.
		if length < uint64(wimMetadataEntryBaseLen) || length > uint64(remaining) {
			break
		}
		if cap(record) < int(length) {
			record = make([]byte, int(length))
		} else {
			record = record[:int(length)]
		}
		copy(record, header[:])
		if _, err := io.ReadFull(reader, record[8:]); err != nil {
			return nil, err
		}
		child, err := parseWIMEntry(record, 0, dir.path)
		if err != nil {
			return nil, fmt.Errorf("entry under %s: %w", dir.path, err)
		}
		if !validWIMName(child.name) {
			break
		}
		if location, ok := w.lookupResource(child.hash); ok {
			child.size = location.blobSize
		}
		detachWIMEntry(&child)
		entries = append(entries, child)
		remaining -= int64(length)
	}
	return entries, nil
}
