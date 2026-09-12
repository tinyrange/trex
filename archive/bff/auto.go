package bff

import (
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("bff", 30, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < 8 || p[0] != volumeHeaderSize/headerUnit || p[1] != volumeRecord {
			return nil, auto.ErrNoMatch
		}
		magic := binary.LittleEndian.Uint16(p[2:])
		if magic != ordinaryMagic && magic != packedMagic {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(Builtin, r, o, starlark.Tuple{starlark.String("maximum_entries"), starlark.MakeInt(o.MaxEntries)}, starlark.Tuple{starlark.String("maximum_decoded_bytes"), starlark.MakeInt64(o.MaxExpandedBytes)})
	})
}
