package starlarkfrontend

import (
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
	storagenative "github.com/tinyrange/trex/storage/native"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

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
