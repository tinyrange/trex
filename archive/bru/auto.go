package bru

import (
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("bru", 90, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < headerSize {
			return nil, auto.ErrNoMatch
		}
		kind, err := number(p[176:180])
		if err != nil || kind != archiveRecord {
			return nil, auto.ErrNoMatch
		}
		seq, err := number(p[136:144])
		if err != nil || seq != 0 {
			return nil, auto.ErrNoMatch
		}
		if _, err := number(p[152:160]); err != nil {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(Builtin, r, o, starlark.Tuple{starlark.String("maximum_entries"), starlark.MakeInt(o.MaxEntries)})
	})
}
