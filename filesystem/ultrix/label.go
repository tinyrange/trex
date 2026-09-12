// Package ultrix reads the DEC/Ultrix partition label. On-disk facts are
// documented in NetBSD sys/dev/dec/dec_boot.h; no OS disk service is used.
package ultrix

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type Partition struct {
	Index         int
	Start, Blocks uint32
	Data          starfile.File
}

// Open preserves all eight slots and their overlapping disk views. In
// particular, the whole-disk slot overlaps individual filesystems; there is
// no implicit filesystem selection, mounting or inferred partition type.
func Open(file starfile.File) ([]Partition, error) {
	const offset = 31*512 + 440
	if file.Size() < offset+72 {
		return nil, fmt.Errorf("ultrix label: truncated input")
	}
	var label [72]byte
	if _, err := starfile.ReadFullAt(file, label[:], offset); err != nil {
		return nil, err
	}
	var order binary.ByteOrder
	switch {
	case binary.LittleEndian.Uint32(label[:]) == 0x32957:
		order = binary.LittleEndian
	case binary.BigEndian.Uint32(label[:]) == 0x32957:
		order = binary.BigEndian
	default:
		return nil, fmt.Errorf("ultrix label: bad magic")
	}
	if order.Uint32(label[4:]) != 1 {
		return nil, fmt.Errorf("ultrix label: inactive partition table")
	}
	result := make([]Partition, 8)
	for i := range result {
		blocks, start := order.Uint32(label[8+i*8:]), order.Uint32(label[12+i*8:])
		if int32(blocks) < 0 || int32(start) < 0 {
			return nil, fmt.Errorf("ultrix label: negative partition geometry")
		}
		p := Partition{Index: i, Start: start, Blocks: blocks}
		if blocks != 0 {
			offset, size := int64(start)*512, int64(blocks)*512
			if offset > file.Size() || size > file.Size()-offset {
				return nil, fmt.Errorf("ultrix label: partition %d outside image", i)
			}
			p.Data = &starfile.Slice{Base: file, Offset: offset, Length: size}
		}
		result[i] = p
	}
	return result, nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("ultrix_label", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("ultrix label: expected file")
	}
	parts, err := Open(file)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(parts))
	for i, p := range parts {
		var data starlark.Value = starlark.None
		if p.Data != nil {
			data = p.Data
		}
		values[i] = starfile.NewRecord(starlark.StringDict{"index": starlark.MakeInt(i), "name": starlark.String(string(rune('a' + i))), "start_block": starlark.MakeUint(uint(p.Start)), "blocks": starlark.MakeUint(uint(p.Blocks)), "data": data})
	}
	return starfile.NewRecord(starlark.StringDict{"block_size": starlark.MakeInt(512), "partitions": starlark.NewList(values)}), nil
}
