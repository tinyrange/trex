package ntfs

import (
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("ntfs", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if len(prefix) < 11 || string(prefix[3:11]) != "NTFS    " {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(NTFSBuiltin, source, options)
	})
}
