package starlarkfrontend

import (
	"runtime"
	"runtime/debug"
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
	"go.starlark.net/starlark"
)

func TestRuntimeReleaseMemoryPreservesLiveResourcesAndLimit(t *testing.T) {
	thread := &starlark.Thread{Name: "release-memory-test"}
	resources := installRuntimeResources(thread)
	defer resources.Close()
	cache, source := resources.NewCacheSource()
	key := bytecache.Key{Source: source}
	calls := 0
	load := func() ([]byte, error) {
		calls++
		return []byte("live immutable content"), nil
	}
	if _, err := cache.Get(key, load); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	limit := debug.SetMemoryLimit(-1) // Query only; negative does not change it.
	value, err := runtimeReleaseMemoryBuiltin(thread, nil, nil, nil)
	runtime.ReadMemStats(&after)
	if err != nil || value != starlark.None {
		t.Fatal(value, err)
	}
	if after.NumGC <= before.NumGC {
		t.Fatal("explicit collection did not run")
	}
	if debug.SetMemoryLimit(-1) != limit {
		t.Fatal("memory limit changed")
	}
	data, err := cache.Get(key, load)
	if err != nil || string(data) != "live immutable content" || calls != 1 {
		t.Fatal("live cache was evicted or invalidated", calls, err)
	}
	if _, err := runtimeReleaseMemoryBuiltin(thread, nil, starlark.Tuple{starlark.True}, nil); err == nil {
		t.Fatal("unexpected argument accepted")
	}
}
