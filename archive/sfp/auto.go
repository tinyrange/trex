package sfp

import (
	"bytes"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("sfp", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("SFP\x00")) {
			return nil, auto.ErrNoMatch
		}
		value, err := Open(adapter.File(source), options.MaxEntries, 64<<20)
		if err != nil {
			return nil, err
		}
		return adapter.Parsed(value, options)
	})
}
