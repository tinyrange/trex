package hfs

import (
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("hfs", 30, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if !(len(p) >= 1026 && string(p[1024:1026]) == "BD") {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(Builtin, r, o, starlark.Tuple{starlark.String("maximum_entries"), starlark.MakeInt(o.MaxEntries)})
	})
}
