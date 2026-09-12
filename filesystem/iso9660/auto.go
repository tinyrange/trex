package iso9660

import (
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("iso9660", 50, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if len(prefix) < 32774 || string(prefix[32769:32774]) != "CD001" {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(ISO9660Builtin, source, options)
	})
}
