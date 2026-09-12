package cab

import (
	"bytes"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("cab", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("MSCF")) {
			return nil, auto.ErrNoMatch
		}
		value, err := Open(source, true)
		if err != nil {
			return nil, err
		}
		return adapter.Parsed(value, options)
	})
}
