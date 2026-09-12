package ods2

import (
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("ods2", 30, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if !(len(p) >= 1020 && string(p[1008:1020]) == "DECFILE11B  ") {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(Builtin, r, o, starlark.Tuple{starlark.String("maximum_entries"), starlark.MakeInt(o.MaxEntries)}, starlark.Tuple{starlark.String("maximum_depth"), starlark.MakeInt(o.MaxDepth)})
	})
}
