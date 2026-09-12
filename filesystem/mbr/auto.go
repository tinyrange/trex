package mbr

import (
	"encoding/binary"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("mbr", 70, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if len(prefix) < 512 || prefix[510] != 0x55 || prefix[511] != 0xaa {
			return nil, auto.ErrNoMatch
		}
		found := false
		for i := 0; i < 4; i++ {
			p := prefix[446+i*16 : 462+i*16]
			if p[4] != 0 && binary.LittleEndian.Uint32(p[12:]) != 0 {
				found = true
			}
		}
		if !found {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(MBRBuiltin, source, options)
	})
}
