package tararchive

import (
	"archive/tar"
	"bytes"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("tar", 90, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if len(prefix) < 512 {
			return nil, auto.ErrNoMatch
		}
		_, err := tar.NewReader(bytes.NewReader(prefix[:512])).Next()
		if err != nil {
			if len(prefix) < 1024 || !bytes.Equal(prefix[:1024], make([]byte, 1024)) {
				return nil, auto.ErrNoMatch
			}
		}
		value, err := Open(adapter.File(source), options.MaxEntries)
		if err != nil {
			return nil, err
		}
		return adapter.Parsed(value, options)
	})
}
