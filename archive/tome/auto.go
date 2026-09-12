package tome

import (
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("tome", 30, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if !(len(p) >= 4 && binary.BigEndian.Uint32(p) == 0x6b630001) {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(Builtin, r, o, starlark.Tuple{starlark.String("maximum_entries"), starlark.MakeInt(o.MaxEntries)}, starlark.Tuple{starlark.String("maximum_decoded_bytes"), starlark.MakeInt64(o.MaxExpandedBytes)})
	})
}
