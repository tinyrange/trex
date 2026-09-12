package wim

import (
	"bytes"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("wim", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("MSWIM\x00\x00\x00")) {
			return nil, auto.ErrNoMatch
		}
		value, err := Open(source)
		if err != nil {
			return nil, err
		}
		return adapter.Parsed(value, options)
	})
}
