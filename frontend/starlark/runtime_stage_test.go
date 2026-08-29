package starlarkfrontend

import (
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
	storagenative "github.com/tinyrange/trex/storage/native"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type stageTestSource struct{ starlark.Value }

func TestStageCacheReusesAndFreezesResults(t *testing.T) {
	thread := &starlark.Thread{Name: "stage-cache-test"}
	cache := &starlarkStageCache{entries: make(map[stageCacheKey]starlark.Value)}
	source := &starfile.Bytes{Name: "source", Data: []byte("input")}
	calls := 0
	function := starlark.NewBuiltin("stage", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		calls++
		out := starlark.NewDict(1)
		_ = out.SetKey(starlark.String("calls"), starlark.MakeInt(calls))
		return out, nil
	})
	compute := func(options string) starlark.Value {
		value, err := cache.computeBuiltin(thread, nil, starlark.Tuple{
			starlark.String("media"), source, starlark.String(options), function,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	first := compute("same")
	second := compute("same")
	if first != second || calls != 1 {
		t.Fatalf("stage cache returned %p and %p after %d calls", first, second, calls)
	}
	if err := first.(*starlark.Dict).SetKey(starlark.String("changed"), starlark.True); err == nil {
		t.Fatal("cached stage result remained mutable")
	}
	_ = compute("changed")
	if calls != 2 {
		t.Fatalf("option change left calls = %d, want 2", calls)
	}
	statsValue, err := cache.Attr("stats")
	if err != nil {
		t.Fatal(err)
	}
	stats := statsValue.(*starlarkRecord)
	if stats.Values["hits"].String() != "1" || stats.Values["misses"].String() != "2" {
		t.Fatalf("stage cache stats = %s", stats)
	}
}

func TestRuntimeStatsReportsBoundedCacheMetrics(t *testing.T) {
	thread := &starlark.Thread{Name: "runtime-stats-test"}
	resources := installRuntimeResources(thread)
	defer resources.Close()
	cache, source := resources.NewCacheSource()
	if _, err := cache.Get(bytecache.Key{Source: source}, func() ([]byte, error) {
		return []byte("decoded"), nil
	}); err != nil {
		t.Fatal(err)
	}
	value, err := runtimeStatsBuiltin(thread, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stats := value.(*starlarkRecord)
	if stats.Values["decompressed_bytes"].String() != "7" || stats.Values["cache_peak_retained_bytes"].String() != "7" {
		t.Fatalf("runtime stats = %s", stats)
	}
}

func TestWriteRejectsOversizedFinalOutputBeforeCreation(t *testing.T) {
	value := &starfile.Bytes{Name: "large", Data: []byte("too large")}
	_, err := starlark.Call(&starlark.Thread{Name: "write-limit-test"}, storagenative.Builtins()["write"].(starlark.Callable), starlark.Tuple{starlark.String("must-not-exist"), value}, []starlark.Tuple{
		{starlark.String("max_bytes"), starlark.MakeInt(1)},
	})
	if err == nil {
		t.Fatal("write accepted an oversized final output")
	}
}
