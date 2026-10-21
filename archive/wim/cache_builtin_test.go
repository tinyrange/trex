package wim

import (
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func TestBuiltinCacheBudget(t *testing.T) {
	for _, limit := range []int64{-1, 0, 4, 16} {
		source := &starfile.Bytes{Name: "empty.wim", Data: minimalWIMHeader(0, 0)}
		value, err := Builtin(nil, nil, starlark.Tuple{source}, []starlark.Tuple{{starlark.String("cache_bytes"), starlark.MakeInt64(limit)}})
		if limit < 0 {
			if err == nil {
				t.Fatal("negative budget accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		archive := value.(*Archive)
		loads := 0
		for i := 0; i < 2; i++ {
			_, err = archive.cacheStore.Get(bytecache.Key{}, func() ([]byte, error) { loads++; return make([]byte, 8), nil })
			if err != nil {
				t.Fatal(err)
			}
		}
		want := 1
		if limit < 8 {
			want = 2
		}
		if loads != want || archive.cacheStore.Stats().Bytes > limit {
			t.Fatalf("budget %d: loads=%d stats=%+v", limit, loads, archive.cacheStore.Stats())
		}
	}
}
