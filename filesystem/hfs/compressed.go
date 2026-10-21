package hfs

import (
	"fmt"

	"github.com/tinyrange/trex/compression/decmpfs"
	starfile "github.com/tinyrange/trex/storage/star"
)

func compressedData(attr, resource starfile.File) (starfile.File, uint32, error) {
	data, kind, err := decmpfs.Open(attr, resource)
	if err != nil {
		return nil, 0, err
	}
	return starfile.NewReader("decmpfs", data), kind, nil
}

func decodeCompressed(v *Volume, raw bool) error {
	for i := range v.Entries {
		e := &v.Entries[i]
		if e.Kind != "file" || e.OwnerFlags&0x20 == 0 || (len(e.FinderInfo) >= 8 && string(e.FinderInfo[:8]) == "hlnkhfs+") || raw {
			continue
		}
		data, kind, err := compressedData(e.Xattrs["com.apple.decmpfs"], e.Resource)
		if err != nil {
			return fmt.Errorf("hfs+: %s: %w", e.Path, err)
		}
		e.RawData, e.Data, e.CompressionType = e.Data, data, kind
	}
	return nil
}
