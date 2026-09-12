package vmsbackup

import (
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("vmsbackup", 30, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if !(len(p) >= 8 && string(p[:8]) == "\x00\x01\x00\x04\x01\x00\x01\x00") {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(FilesBuiltin, r, o, starlark.Tuple{starlark.String("maximum_files"), starlark.MakeInt(o.MaxEntries)}, starlark.Tuple{starlark.String("maximum_records"), starlark.MakeInt(o.MaxEntries)}, starlark.Tuple{starlark.String("maximum_blocks"), starlark.MakeInt(o.MaxEntries)}, starlark.Tuple{starlark.String("maximum_block_size"), starlark.MakeInt64(o.MaxExpandedBytes)})
	})
}
