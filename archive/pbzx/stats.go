package pbzx

import (
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type fileValue struct {
	*starfile.ReaderValue
	file *File
}

func (v *fileValue) AttrNames() []string { return append(v.ReaderValue.AttrNames(), "stats") }
func (v *fileValue) Attr(name string) (starlark.Value, error) {
	if name != "stats" {
		return v.ReaderValue.Attr(name)
	}
	s := v.file.Stats()
	return statsDict(starlark.StringDict{
		"xz_chunks": starlark.MakeUint64(s.XZChunks), "xz_bytes": starlark.MakeUint64(s.XZBytes),
		"replay_blocks": starlark.MakeUint64(s.ReplayBlocks), "replay_bytes": starlark.MakeUint64(s.ReplayBytes),
		"replay_block_size": starlark.MakeInt(ReplayBlockSize),
		"decoded_cache":     cacheStatsValue(s.DecodedCache), "replay_cache": cacheStatsValue(s.ReplayCache),
	}), nil
}
func statsDict(values starlark.StringDict) *starlark.Dict {
	d := starlark.NewDict(len(values))
	for k, v := range values {
		_ = d.SetKey(starlark.String(k), v)
	}
	return d
}
func cacheStatsValue(s bytecache.Stats) *starlark.Dict {
	return statsDict(starlark.StringDict{
		"hits": starlark.MakeUint64(s.Hits), "misses": starlark.MakeUint64(s.Misses),
		"evictions": starlark.MakeUint64(s.Evictions), "loads": starlark.MakeUint64(s.Loads),
		"loaded_bytes": starlark.MakeUint64(s.LoadedBytes), "bytes": starlark.MakeInt64(s.Bytes),
		"entries": starlark.MakeInt(s.Entries),
	})
}
