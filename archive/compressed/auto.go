package compressed

import (
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

func init() {
	for format, magic := range map[string]byte{"compress": 0x9d, "pack": 0x1e} {
		auto.Register(format, 10, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
			if len(p) < 2 || p[0] != 0x1f || p[1] != magic {
				return nil, auto.ErrNoMatch
			}
			decoded, err := Open(r, format, o.MaxExpandedBytes)
			if err != nil {
				return nil, err
			}
			return &auto.DecodedView{Reader: decoded}, nil
		})
	}
}
