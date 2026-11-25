package wim

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

type derivedChunkCache struct {
	ctx      context.Context
	identity [sha256.Size]byte
	records  storage.DerivedCache
}

// The caller supplies a source digest covering the archive bytes and its
// member selection. This identity never substitutes for source verification.
func verifiedDerivedChunks(thread *starlark.Thread, identity string) (*derivedChunkCache, error) {
	data, err := hex.DecodeString(identity)
	if err != nil || len(data) != sha256.Size {
		return nil, fmt.Errorf("wim: verified cache identity must be a SHA-256 digest")
	}
	if resources, err := lifecycle.ForThread(thread); err == nil && resources.Derived != nil {
		return &derivedChunkCache{resources.Context(), [sha256.Size]byte(data), resources.Derived}, nil
	}
	return nil, nil
}

func derivedWIMMember(file storage.Reader) *derivedChunkCache {
	member, ok := file.(*File)
	if !ok || member.location == nil || member.location.archive != member.archive || member.location.external != nil {
		return nil
	}
	parent := member.archive.derivedChunks
	if parent == nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(parent.identity[:])
	hash.Write([]byte(member.entry.path))
	return &derivedChunkCache{parent.ctx, [sha256.Size]byte(hash.Sum(nil)), parent.records}
}

func (w *Archive) readDerivedChunk(resource wimResource, chunk wimChunk) ([]byte, error) {
	cache := w.derivedChunks
	if cache == nil || chunk.outputSize < 4096 || chunk.inSize == int64(chunk.outputSize) || chunk.outputSize > 64<<20 {
		return w.readChunk(resource, chunk)
	}
	key := make([]byte, 0, sha256.Size+64)
	key = append(key, cache.identity[:]...)
	for _, field := range []int64{resource.offset, resource.size, resource.originalSize, int64(resource.flags),
		int64(resource.compression), chunk.inOffset, chunk.inSize, int64(chunk.outputSize)} {
		key = binary.LittleEndian.AppendUint64(key, uint64(field))
	}
	return storage.ReadDerivedLZ4Block(cache.ctx, cache.records, storage.DerivedKey("wim.chunk-lz4/v1", sha256.Sum256(key)), chunk.outputSize, func() ([]byte, error) {
		return w.readChunk(resource, chunk)
	})
}
