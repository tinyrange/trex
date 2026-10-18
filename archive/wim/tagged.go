package wim

import (
	"encoding/binary"
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// WIM dentry extensions are (LE32 tag, LE32 payload length, payload),
// padded to eight bytes. Keep unknown and repeated tags for read-only inspection;
// this does not manufacture or apply NTFS security/cache metadata.
func parseWIMTaggedItems(data []byte) ([]wimTaggedItem, error) {
	var result []wimTaggedItem
	for len(data) > 0 {
		if len(data) < 8 {
			return nil, fmt.Errorf("wim: truncated tagged-item header")
		}
		tag := binary.LittleEndian.Uint32(data)
		n := uint64(binary.LittleEndian.Uint32(data[4:]))
		total := uint64(8) + ((n + 7) &^ uint64(7))
		if total > uint64(len(data)) {
			return nil, fmt.Errorf("wim: tagged item %d exceeds directory entry", tag)
		}
		result = append(result, wimTaggedItem{tag: tag, data: data[8 : 8+n]})
		data = data[total:]
	}
	return result, nil
}

func wimTaggedItemsValue(items []wimTaggedItem) starlark.Value {
	values := make([]starlark.Value, 0, len(items))
	for _, item := range items {
		values = append(values, starfile.NewRecord(starlark.StringDict{
			"tag": starlark.MakeUint(uint(item.tag)), "data": starlark.Bytes(item.data),
		}))
	}
	return starlark.NewList(values)
}
