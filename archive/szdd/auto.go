package szdd

import (
	"bytes"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func init() {
	auto.Register("szdd", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !(bytes.HasPrefix(prefix, []byte("SZDD\x88\xf0\x27\x33")) || bytes.HasPrefix(prefix, []byte("SZ \x88\xf0\x27\x33\xd1"))) {
			return nil, auto.ErrNoMatch
		}
		data, err := decodeSZDD(adapter.File(source), options.MaxExpandedBytes)
		decoded := &starfile.Bytes{Data: data}
		if err != nil {
			return nil, err
		}
		if decoded.Size() > options.MaxExpandedBytes {
			return nil, auto.ErrLimit
		}
		return &auto.DecodedView{Reader: decoded}, nil
	})
}
