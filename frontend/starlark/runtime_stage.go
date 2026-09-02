package starlarkfrontend

import (
	"runtime"

	"go.starlark.net/starlark"
)

func runtimeNamespace() namespace {
	return namespace{name: "runtime", attrs: starlark.StringDict{
		"stats": starlark.NewBuiltin("stats", runtimeStatsBuiltin),
	}}
}

func runtimeStatsBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("runtime.stats", args, kwargs); err != nil {
		return nil, err
	}
	resources, err := resourcesForThread(thread)
	if err != nil {
		return nil, err
	}
	cache := resources.CacheStats()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return newStarlarkRecord(starlark.StringDict{
		"cache_entries":             starlark.MakeInt(cache.Entries),
		"cache_evictions":           starlark.MakeUint64(cache.Evictions),
		"cache_hits":                starlark.MakeUint64(cache.Hits),
		"cache_misses":              starlark.MakeUint64(cache.Misses),
		"cache_retained_bytes":      starlark.MakeInt64(cache.Bytes),
		"cache_peak_retained_bytes": starlark.MakeInt64(cache.PeakBytes),
		"decompressed_bytes":        starlark.MakeUint64(resources.Metrics().Decompressed.Load()),
		"heap_alloc_bytes":          starlark.MakeUint64(memory.HeapAlloc),
		"heap_sys_bytes":            starlark.MakeUint64(memory.HeapSys),
		"nbd_read_bytes":            starlark.MakeUint64(resources.Metrics().NBDReadBytes.Load()),
		"nbd_write_bytes":           starlark.MakeUint64(resources.Metrics().NBDWriteBytes.Load()),
		"source_read_bytes":         starlark.MakeUint64(resources.Metrics().SourceReadBytes.Load()),
		"streamed_bytes":            starlark.MakeUint64(resources.Metrics().Streamed.Load()),
		"runtime_sys_bytes":         starlark.MakeUint64(memory.Sys),
		"total_allocated_bytes":     starlark.MakeUint64(memory.TotalAlloc),
	}), nil
}
