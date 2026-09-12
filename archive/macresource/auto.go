package macresource

import (
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("mac_resource", 95, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < 16 {
			return nil, auto.ErrNoMatch
		}
		be := binary.BigEndian
		data, offset, size, mapsize := int64(be.Uint32(p)), int64(be.Uint32(p[4:])), int64(be.Uint32(p[8:])), int64(be.Uint32(p[12:]))
		if data < 16 || offset < 16 || mapsize < 30 || data > r.Size() || size > r.Size()-data || offset > r.Size() || mapsize > r.Size()-offset || (data < offset+mapsize && offset < data+size) {
			return nil, auto.ErrNoMatch
		}
		var header [28]byte
		if _, err := r.ReadAt(header[:], offset); err != nil {
			return nil, err
		}
		types, names := int64(be.Uint16(header[24:])), int64(be.Uint16(header[26:]))
		if types < 28 || types+2 > mapsize || names < 28 || names > mapsize {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(Builtin, r, o, starlark.Tuple{starlark.String("maximum_entries"), starlark.MakeInt(o.MaxEntries)}, starlark.Tuple{starlark.String("maximum_decoded_bytes"), starlark.MakeInt64(o.MaxExpandedBytes)})
	})
}
