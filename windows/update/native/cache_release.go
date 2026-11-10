package native

import (
	"fmt"
	"github.com/tinyrange/trex/archive/wim"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func releaseReadCachesBuiltin(base *wim.Archive, stages []*uup.CumulativeStage, cache *uup.StageMetadataCache) *starlark.Builtin {
	return starlark.NewBuiltin("release_read_caches", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var baseChunkCacheBytes int64 = -1
		if err := starlark.UnpackArgs("release_read_caches", args, kwargs, "base_chunk_cache_bytes?", &baseChunkCacheBytes); err != nil {
			return nil, err
		}
		if baseChunkCacheBytes < -1 {
			return nil, fmt.Errorf("base_chunk_cache_bytes must be nonnegative or -1 (unchanged)")
		}
		if baseChunkCacheBytes >= 0 {
			base.SetChunkCacheLimit(baseChunkCacheBytes)
		}
		// Emptying alone would let runtime reads regrow the construction budget.
		cache.SetLimit(maximumServicingWIMCache)
		for _, stage := range stages {
			stage.ReleaseReadCaches()
		}
		base.ReleaseReadCaches()
		return starlark.None, nil
	})
}
