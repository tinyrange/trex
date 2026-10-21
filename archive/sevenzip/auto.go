package sevenzip

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/archive/internal/sfx"
	"hash/crc32"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("7z", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if bytes.HasPrefix(prefix, []byte("MZ")) {
			candidates, err := sfx.Candidates(source, []byte("7z\xbc\xaf\x27\x1c"), 16<<20)
			if err != nil {
				return nil, err
			}
			for _, candidate := range candidates {
				var header [32]byte
				if _, err := candidate.ReadAt(header[:], 0); err != nil {
					continue
				}
				if crc32.ChecksumIEEE(header[12:]) != binary.LittleEndian.Uint32(header[8:]) {
					continue
				}
				value, err := Open(candidate, options.MaxEntries, 64<<20, 64<<20)
				if err != nil {
					return nil, err
				}
				return adapter.Parsed(value, options)
			}
			return nil, auto.ErrNoMatch
		}
		if !bytes.HasPrefix(prefix, []byte("7z\xbc\xaf\x27\x1c")) {
			return nil, auto.ErrNoMatch
		}
		value, err := Open(source, options.MaxEntries, 64<<20, 64<<20)
		if err != nil {
			return nil, err
		}
		return adapter.Parsed(value, options)
	})
}
