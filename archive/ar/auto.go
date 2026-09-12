package ar

import (
	"bytes"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("ar", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("!<arch>\n")) {
			return nil, auto.ErrNoMatch
		}
		value, err := Open(adapter.File(source))
		if err != nil {
			return nil, err
		}
		return adapter.Parsed(value, options)
	})
}
