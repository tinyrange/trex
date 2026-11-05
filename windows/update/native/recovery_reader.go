package native

import (
	"crypto/sha256"
	"fmt"

	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
)

// Generation is eager once to establish exact encoded length and identity.
// The returned reader retains neither that buffer nor a closure over it.
// Cache keys are scoped to a component plan and include index AND file time.
func newRecoveryReader(cache *bytecache.Cache, key bytecache.Key, generate func() ([]byte, error)) (*reopenedStageReader, error) {
	data, err := cache.Get(key, generate)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > 128<<20 {
		return nil, fmt.Errorf("generated recovery exceeds read bound")
	}
	hash := sha256.Sum256(data)
	return &reopenedStageReader{
		size: int64(len(data)), expectedSHA256: &hash, cache: cache, key: key,
		open: func() (storage.Reader, error) {
			data, err := generate()
			if err != nil {
				return nil, err
			}
			return &starfile.Bytes{Data: data}, nil
		},
	}, nil
}
