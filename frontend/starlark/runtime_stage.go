package starlarkfrontend

import (
	"fmt"
	"reflect"
	"sort"
	"sync"

	"go.starlark.net/starlark"
)

func runtimeNamespace() namespace {
	return namespace{name: "runtime", attrs: starlark.StringDict{
		"stage_cache": starlark.NewBuiltin("stage_cache", runtimeStageCacheBuiltin),
		"stats":       starlark.NewBuiltin("stats", runtimeStatsBuiltin),
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
	return newStarlarkRecord(starlark.StringDict{
		"cache_entries":             starlark.MakeInt(cache.Entries),
		"cache_evictions":           starlark.MakeUint64(cache.Evictions),
		"cache_hits":                starlark.MakeUint64(cache.Hits),
		"cache_misses":              starlark.MakeUint64(cache.Misses),
		"cache_retained_bytes":      starlark.MakeInt64(cache.Bytes),
		"cache_peak_retained_bytes": starlark.MakeInt64(cache.PeakBytes),
		"decompressed_bytes":        starlark.MakeUint64(resources.Metrics().Decompressed.Load()),
		"nbd_read_bytes":            starlark.MakeUint64(resources.Metrics().NBDReadBytes.Load()),
		"nbd_write_bytes":           starlark.MakeUint64(resources.Metrics().NBDWriteBytes.Load()),
		"source_read_bytes":         starlark.MakeUint64(resources.Metrics().SourceReadBytes.Load()),
		"streamed_bytes":            starlark.MakeUint64(resources.Metrics().Streamed.Load()),
	}), nil
}

func runtimeStageCacheBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("runtime.stage_cache", args, kwargs); err != nil {
		return nil, err
	}
	return &starlarkStageCache{entries: make(map[stageCacheKey]starlark.Value)}, nil
}

type stageCacheKey struct {
	name        string
	sourceType  string
	sourceID    uintptr
	optionsType string
	optionsHash uint32
	optionsText string
}

type starlarkStageCache struct {
	mu      sync.Mutex
	entries map[stageCacheKey]starlark.Value
	hits    uint64
	misses  uint64
}

func (c *starlarkStageCache) String() string       { return "<runtime.stage_cache>" }
func (c *starlarkStageCache) Type() string         { return "runtime.stage_cache" }
func (c *starlarkStageCache) Freeze()              {}
func (c *starlarkStageCache) Truth() starlark.Bool { return starlark.True }
func (c *starlarkStageCache) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", c.Type())
}
func (c *starlarkStageCache) Attr(name string) (starlark.Value, error) {
	switch name {
	case "compute":
		return starlark.NewBuiltin("stage_cache.compute", c.computeBuiltin), nil
	case "stats":
		c.mu.Lock()
		defer c.mu.Unlock()
		return newStarlarkRecord(starlark.StringDict{
			"entries": starlark.MakeInt(len(c.entries)),
			"hits":    starlark.MakeUint64(c.hits),
			"misses":  starlark.MakeUint64(c.misses),
		}), nil
	}
	return nil, nil
}
func (c *starlarkStageCache) AttrNames() []string { return []string{"compute", "stats"} }

func stageSourceID(source starlark.Value) (uintptr, error) {
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		if value.IsNil() {
			return 0, fmt.Errorf("stage source must not be nil")
		}
		return value.Pointer(), nil
	default:
		return 0, fmt.Errorf("stage source must be an identity-bearing runtime object, got %s", source.Type())
	}
}

func (c *starlarkStageCache) computeBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var source, options, function starlark.Value
	callArgs := starlark.Tuple{}
	callKwargs := starlark.NewDict(0)
	if err := starlark.UnpackArgs("stage_cache.compute", args, kwargs,
		"name", &name,
		"source", &source,
		"options", &options,
		"function", &function,
		"args?", &callArgs,
		"kwargs?", &callKwargs,
	); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, fmt.Errorf("stage_cache.compute: name must not be empty")
	}
	callable, ok := function.(starlark.Callable)
	if !ok {
		return nil, fmt.Errorf("stage_cache.compute: function got %s, want callable", function.Type())
	}
	sourceID, err := stageSourceID(source)
	if err != nil {
		return nil, fmt.Errorf("stage_cache.compute: %w", err)
	}
	optionsHash, err := options.Hash()
	if err != nil {
		return nil, fmt.Errorf("stage_cache.compute: options must be hashable: %w", err)
	}
	key := stageCacheKey{
		name:        name,
		sourceType:  source.Type(),
		sourceID:    sourceID,
		optionsType: options.Type(),
		optionsHash: optionsHash,
		optionsText: options.String(),
	}
	c.mu.Lock()
	if cached, ok := c.entries[key]; ok {
		c.hits++
		c.mu.Unlock()
		return cached, nil
	}
	c.misses++
	c.mu.Unlock()

	items := callKwargs.Items()
	sort.Slice(items, func(i, j int) bool { return items[i][0].String() < items[j][0].String() })
	callKeywords := make([]starlark.Tuple, len(items))
	for index, item := range items {
		if _, ok := item[0].(starlark.String); !ok {
			return nil, fmt.Errorf("stage_cache.compute: keyword name got %s, want string", item[0].Type())
		}
		callKeywords[index] = starlark.Tuple{item[0], item[1]}
	}
	result, err := starlark.Call(thread, callable, callArgs, callKeywords)
	if err != nil {
		return nil, err
	}
	result.Freeze()
	c.mu.Lock()
	if existing, ok := c.entries[key]; ok {
		result = existing
	} else {
		c.entries[key] = result
	}
	c.mu.Unlock()
	return result, nil
}
