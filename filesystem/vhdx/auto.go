package vhdx

import (
	"bytes"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("vhdx", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !(bytes.HasPrefix(prefix, []byte("vhdxfile"))) {
			return nil, auto.ErrNoMatch
		}
		decoded, err := VHDXBuiltin(nil, nil, starlark.Tuple{adapter.File(source)}, nil)
		if err != nil {
			return nil, err
		}
		return &auto.DecodedView{Reader: decoded.(storage.Reader)}, nil
	})
}
