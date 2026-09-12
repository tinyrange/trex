package compactpro

import (
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("compactpro", 90, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < 8 || p[0] != 1 || p[1] != 1 {
			return nil, auto.ErrNoMatch
		}
		offset := int64(binary.BigEndian.Uint32(p[4:]))
		if offset < 8 || offset > r.Size()-7 {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(Builtin, r, o, starlark.Tuple{starlark.String("maximum_entries"), starlark.MakeInt(o.MaxEntries)}, starlark.Tuple{starlark.String("maximum_decoded_bytes"), starlark.MakeInt64(o.MaxExpandedBytes)})
	})
}
