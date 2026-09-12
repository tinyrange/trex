package udf

import (
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("udf", 40, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		found := false
		for sector := 16; sector < 32; sector++ {
			off := sector*2048 + 1
			if len(prefix) >= off+5 && (string(prefix[off:off+5]) == "NSR02" || string(prefix[off:off+5]) == "NSR03") {
				found = true
				break
			}
		}
		if !found {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(UDFBuiltin, source, options)
	})
}
