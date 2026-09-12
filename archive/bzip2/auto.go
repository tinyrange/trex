package bzip2

import (
	"bytes"
	"io"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("bzip2", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("BZh")) {
			return nil, auto.ErrNoMatch
		}
		decoded := NewReader(source, options.MaxExpandedBytes)
		// Validate the first decoded prefix without reading the entire stream.
		var first [1]byte
		if _, err := decoded.ReadAt(first[:], 0); err != nil && err != io.EOF {
			return nil, err
		}
		return &auto.DecodedView{Reader: decoded}, nil
	})
}
