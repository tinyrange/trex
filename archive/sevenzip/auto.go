package sevenzip

import (
	"bytes"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("7z", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("7z\xbc\xaf\x27\x1c")) {
			return nil, auto.ErrNoMatch
		}
		value, err := Open(source, options.MaxEntries, 64<<20, 64<<20)
		if err != nil {
			return nil, err
		}
		return adapter.Parsed(value, options)
	})
}
