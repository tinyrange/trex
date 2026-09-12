package irix

import (
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("irix_tape", 30, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if !(len(p) >= 4 && binary.BigEndian.Uint32(p) == 0xaced1234) {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(TapeBuiltin, r, o)
	})
}
