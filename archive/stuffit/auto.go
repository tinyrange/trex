package stuffit

import (
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
	"strings"
)

func init() {
	auto.Register("stuffit", 30, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if !(len(p) >= 8 && (string(p[:8]) == "StuffIt " || strings.Contains("|SIT!|ST46|ST50|ST60|ST65|STin|STi2|STi3|STi4|", "|"+string(p[:4])+"|"))) {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(Builtin, r, o, starlark.Tuple{starlark.String("maximum_entries"), starlark.MakeInt(o.MaxEntries)}, starlark.Tuple{starlark.String("maximum_decoded_bytes"), starlark.MakeInt64(o.MaxExpandedBytes)})
	})
}
