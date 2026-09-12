package fat

import (
	"encoding/binary"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("fat", 30, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if len(prefix) < 36 {
			return nil, auto.ErrNoMatch
		}
		bps := int(binary.LittleEndian.Uint16(prefix[11:13]))
		spc := int(prefix[13])
		if (prefix[0] != 0xeb && prefix[0] != 0xe9) || bps < 128 || bps > 4096 || bps&(bps-1) != 0 || spc == 0 || spc&(spc-1) != 0 || prefix[16] == 0 || prefix[16] > 2 || binary.LittleEndian.Uint16(prefix[14:16]) == 0 {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(FATBuiltin, source, options)
	})
}
