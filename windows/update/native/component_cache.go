package native

import (
	bytecache "github.com/tinyrange/trex/storage/cache"
	starvalue "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Keep this closure independent of the staging plan: observing a live disk's
// cache must not retain its no-longer-needed construction inventories.
func componentCacheStatsBuiltin(cache interface{ Stats() bytecache.Stats }) *starlark.Builtin {
	return starlark.NewBuiltin("component_staging.cache_stats", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs("component_staging.cache_stats", args, kwargs); err != nil {
			return nil, err
		}
		s := cache.Stats()
		return starvalue.NewRecord(starlark.StringDict{
			"hits":                starlark.MakeUint64(s.Hits),
			"misses":              starlark.MakeUint64(s.Misses),
			"loads":               starlark.MakeUint64(s.Loads),
			"load_nanoseconds":    starlark.MakeUint64(s.LoadNanoseconds),
			"loaded_bytes":        starlark.MakeUint64(s.LoadedBytes),
			"evictions":           starlark.MakeUint64(s.Evictions),
			"retained_bytes":      starlark.MakeInt64(s.Bytes),
			"peak_retained_bytes": starlark.MakeInt64(s.PeakBytes),
			"entries":             starlark.MakeInt(s.Entries),
		}), nil
	})
}
