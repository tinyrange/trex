package cab

import (
	"fmt"
	"io"

	"github.com/tinyrange/trex/compression/lzx"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
)

// LZX and Quantum have inter-block history. After construction, retain LZX
// restart checkpoints into the original source, and packed Quantum chunks,
// rather than pinning expanded folders. Both remain in the bounded archive
// cache. Uncached ownership and the smaller MSZIP index are unchanged.
func (f *Entry) packedFolder() bool {
	if !f.archive.cache || !f.archive.compactCache.Load() || int(f.file.folder) >= len(f.archive.folders) {
		return false
	}
	folder := f.archive.folders[f.file.folder]
	kind := folder.compression & 0xf
	return folder.blocks >= 256 && (kind == 2 || kind == 3)
}

func (c *Archive) packedFolderData(index int) (starfile.File, error) {
	value, err := c.cacheStore.GetValue(bytecache.Key{Source: c.cacheSource, Kind: 4, Index: index}, func() (any, int64, error) {
		var err error
		var file starfile.File
		folder := c.folders[index]
		if folder.compression&0xf == 3 {
			var payload *folderPayloadReader
			var size int
			payload, size, err = c.folderPayloadReader(folder)
			if err == nil && size == 0 {
				// Preserve the legacy no-CFDATA-output-size fallback.
				for _, member := range c.files {
					if member.folder == 0 {
						size += int(member.size)
					}
				}
			}
			if err == nil {
				windowBits := int(folder.compression >> 8)
				var indexed *lzx.IndexedReader
				indexed, err = lzx.NewIndexedReader(payload, payload.Size(), windowBits, size, 8<<20)
				if err == nil {
					// Account for actual source block sizes as well as checkpoints;
					// raw LZX blocks can require large compressed-input buffers.
					weight := indexed.RetainedBytes() + indexed.ReadCacheReserve()
					return starfile.NewReader("CAB indexed folder", indexed), weight, nil
				}
			}
		} else {
			store, storeErr := starfile.NewPackedFileStore(starfile.PackedChunkBytes, false)
			if storeErr != nil {
				return nil, 0, storeErr
			}
			var data []byte
			data, err = c.readFolderData(folder)
			if err == nil {
				file, err = store.Pack("CAB folder", data)
			}
		}
		if err != nil {
			return nil, 0, err
		}
		weight := file.Size() + 128
		if packed, ok := file.(*starfile.PackedFile); ok {
			weight = packed.RetainedBytes()
		}
		return file, weight + starfile.PackedChunkBytes, nil
	})
	if err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("cab: invalid packed folder cache value")
	}
	return file, nil
}

func (f *Entry) readPackedAt(p []byte, off int64) (int, error) {
	folder, err := f.archive.packedFolderData(int(f.file.folder))
	if err != nil {
		return 0, err
	}
	start, size := int64(f.file.uncompressedStart), f.Size()
	if start > folder.Size() || size > folder.Size()-start {
		return 0, fmt.Errorf("cab: file %q extends past folder data", f.file.name)
	}
	return io.NewSectionReader(folder, start, size).ReadAt(p, off)
}
