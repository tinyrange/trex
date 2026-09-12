package ufs

import (
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("ufs", 30, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if !(len(p) >= 9568 && (binary.BigEndian.Uint32(p[9564:]) == 0x11954 || binary.LittleEndian.Uint32(p[9564:]) == 0x11954)) {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(Builtin, r, o, starlark.Tuple{starlark.String("maximum_entries"), starlark.MakeInt(o.MaxEntries)}, starlark.Tuple{starlark.String("maximum_blocks"), starlark.MakeInt(o.MaxEntries)})
	})
}
