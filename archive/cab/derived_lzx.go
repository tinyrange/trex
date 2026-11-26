package cab

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	"go.starlark.net/starlark"
)

type derivedLZXCache struct {
	ctx      context.Context
	identity [sha256.Size]byte
	records  storage.DerivedCache
	hot      *bytecache.Cache
}

func (c *Archive) bindDerivedLZX(thread *starlark.Thread, identity string) error {
	data, err := hex.DecodeString(identity)
	if err != nil || len(data) != sha256.Size || c.lzxCheckpointBytes == 0 {
		return fmt.Errorf("cab: verified cache identity requires indexed LZX and exact SHA-256 bytes")
	}
	if resources, err := lifecycle.ForThread(thread); err == nil && resources.Derived != nil {
		c.derivedLZX = &derivedLZXCache{resources.Context(), [sha256.Size]byte(data), resources.Derived, bytecache.New(8 << 20)}
	}
	return nil
}

func (f *Entry) readDerivedLZXAt(p []byte, off int64) (int, error) {
	const blockSize = 64 << 10
	cache := f.archive.derivedLZX
	n := 0
	for len(p) > 0 && off < f.Size() {
		index := int(off / blockSize)
		start := int64(index) * blockSize
		size := int(min(f.Size()-start, blockSize))
		id := bytecache.Key{Source: uint64(f.file.folder), Offset: int64(f.file.uncompressedStart), Size: f.Size(), Index: index}
		data, err := cache.hot.Get(id, func() ([]byte, error) {
			var coordinates [sha256.Size + 32]byte
			copy(coordinates[:], cache.identity[:])
			binary.LittleEndian.PutUint64(coordinates[32:], uint64(id.Source))
			binary.LittleEndian.PutUint64(coordinates[40:], uint64(id.Offset))
			binary.LittleEndian.PutUint64(coordinates[48:], uint64(id.Size))
			binary.LittleEndian.PutUint64(coordinates[56:], uint64(index))
			key := storage.DerivedKey("cab.member-lzx-block/v1", sha256.Sum256(coordinates[:]))
			return storage.ReadDerivedLZ4Block(cache.ctx, cache.records, key, size, func() ([]byte, error) {
				data := make([]byte, size)
				if _, err := f.readIndexedLZXAt(data, start); err != nil {
					return nil, err
				}
				return data, nil
			})
		})
		if err != nil {
			return n, err
		}
		read := copy(p, data[off-start:])
		n += read
		off += int64(read)
		p = p[read:]
	}
	if len(p) != 0 {
		return n, io.EOF
	}
	return n, nil
}
