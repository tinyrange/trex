package cfb

import (
	"bytes"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("cfb", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")) {
			return nil, auto.ErrNoMatch
		}
		value, err := Open(adapter.File(source))
		if err != nil {
			return nil, err
		}
		return adapter.Parsed(value, options)
	})
}
