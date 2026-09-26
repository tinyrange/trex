package gzip

import (
	"bytes"
	"io"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("gzip", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("\x1f\x8b")) {
			return nil, auto.ErrNoMatch
		}
		reader, err := Open(source, options.StreamingMaximum())
		if err != nil {
			return nil, err
		}
		var first [1]byte
		if _, err := reader.ReadAt(first[:], 0); err != nil && err != io.EOF {
			return nil, err
		}
		return &auto.DecodedView{Reader: reader}, nil
	})
}
