package gzip

import (
	"bytes"
	"compress/gzip"
	"io"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func init() {
	auto.Register("gzip", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("\x1f\x8b")) {
			return nil, auto.ErrNoMatch
		}
		reader, err := gzip.NewReader(io.NewSectionReader(source, 0, source.Size()))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		data, err := io.ReadAll(io.LimitReader(reader, options.MaxExpandedBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > options.MaxExpandedBytes {
			return nil, auto.ErrLimit
		}
		return &auto.DecodedView{Reader: &starfile.Bytes{Data: data}}, nil
	})
}
