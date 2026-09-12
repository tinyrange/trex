package hunk

import (
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("hunk_load", 30, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < 4 || binary.BigEndian.Uint32(p) != 1011 {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(BuiltinLoad, r, o, starlark.Tuple{starlark.String("maximum_records"), starlark.MakeInt(o.MaxEntries)})
	})
	auto.Register("hunk_objects", 30, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if !(len(p) >= 4 && binary.BigEndian.Uint32(p) == 999) {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(Builtin, r, o, starlark.Tuple{starlark.String("maximum_records"), starlark.MakeInt(o.MaxEntries)})
	})
}
