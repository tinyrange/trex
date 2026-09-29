package tararchive

import (
	"archive/tar"
	"bytes"
	"path"
	"strings"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("tar", 90, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if len(prefix) < 512 {
			return nil, auto.ErrNoMatch
		}
		_, err := tar.NewReader(bytes.NewReader(prefix)).Next()
		if err != nil {
			// Zero sectors are not a positive archive signature. Accept an empty
			// archive only when the containing tree supplies an explicit .tar name.
			if options.Source == nil || !strings.EqualFold(path.Ext(options.Source.Path), ".tar") || len(prefix) < 1024 || !bytes.Equal(prefix[:1024], make([]byte, 1024)) {
				return nil, auto.ErrNoMatch
			}
		}
		if sized, ok := source.(interface{ KnownSize() (int64, bool) }); ok {
			if _, known := sized.KnownSize(); !known {
				return newStreamView(source, options.MaxEntries), nil
			}
		}
		value, err := Open(adapter.File(source), options.MaxEntries)
		if err != nil {
			return nil, err
		}
		return adapter.Parsed(value, options)
	})
}
