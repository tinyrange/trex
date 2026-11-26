package storage

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/pierrec/lz4/v4"
)

// ReadDerivedLZ4Block retains one independently decoded source block. The
// caller's versioned key must bind the exact source and the block coordinates.
// Compression errors and unavailable records leave the original reader usable.
func ReadDerivedLZ4Block(ctx context.Context, cache DerivedCache, key [sha256.Size]byte, size int, build func() ([]byte, error)) ([]byte, error) {
	if size <= 0 || size > 64<<20 {
		return nil, fmt.Errorf("invalid derived LZ4 block size %d", size)
	}
	var plain []byte
	var sourceErr error
	record, err := cache.GetOrBuild(ctx, key, int64(size), func() ([]byte, error) {
		plain, sourceErr = build()
		if sourceErr != nil {
			return nil, sourceErr
		}
		if len(plain) != size {
			sourceErr = fmt.Errorf("derived block has length %d, expected %d", len(plain), size)
			return nil, sourceErr
		}
		encoded := make([]byte, lz4.CompressBlockBound(size))
		count, err := lz4.CompressBlock(plain, encoded, nil)
		if err != nil || count == 0 || count >= size {
			return plain, nil
		}
		return encoded[:count], nil
	})
	if sourceErr != nil || plain != nil {
		return plain, sourceErr
	}
	if err != nil || len(record) == 0 {
		return build()
	}
	if len(record) == size {
		return record, nil
	}
	plain = make([]byte, size)
	count, err := lz4.UncompressBlock(record, plain)
	if err != nil || count != size {
		return build()
	}
	return plain, nil
}
