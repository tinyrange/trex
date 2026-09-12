package kwaj

import (
	"bytes"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("kwaj", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !(bytes.HasPrefix(prefix, []byte("KWAJ\x88\xf0\x27\xd1"))) {
			return nil, auto.ErrNoMatch
		}
		header, err := parseKWAJHeader(adapter.File(source), options.MaxExpandedBytes)
		if err != nil {
			return nil, err
		}
		decoded, err := decodeKWAJHeader(header, options.MaxExpandedBytes)
		if err != nil {
			return nil, err
		}
		if decoded.Size() > options.MaxExpandedBytes {
			return nil, auto.ErrLimit
		}
		return &auto.DecodedView{Reader: decoded}, nil
	})
}
