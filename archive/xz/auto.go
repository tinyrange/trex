package xz

import (
	"bytes"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("xz", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !(bytes.HasPrefix(prefix, []byte("\xfd7zXZ\x00"))) {
			return nil, auto.ErrNoMatch
		}
		decoded, err := Open(source, 64<<20)
		if err != nil {
			return nil, err
		}
		if decoded.Size() > options.MaxExpandedBytes {
			return nil, auto.ErrLimit
		}
		return &auto.DecodedView{Reader: decoded}, nil
	})
}
