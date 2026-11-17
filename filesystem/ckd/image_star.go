package ckd

import (
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// ImageBuiltin constructs uncompressed CKD records through the native writer.
func ImageBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var cylinders, heads, trackSize, device int
	var tracks *starlark.Dict
	if err := starlark.UnpackArgs("ckd_image", args, kwargs, "cylinders", &cylinders, "heads", &heads, "track_size", &trackSize, "device", &device, "tracks?", &tracks); err != nil {
		return nil, err
	}
	if cylinders < 1 || cylinders > 65536 || heads < 1 || heads > 256 || trackSize < 37 || trackSize > 1<<20 || device < 0 || device > 255 {
		return nil, fmt.Errorf("ckd_image: invalid geometry or device code")
	}
	out := map[uint32][]Record{}
	if tracks != nil {
		for _, item := range tracks.Items() {
			t, err := starlark.AsInt32(item[0])
			if err != nil || t < 0 || uint64(t) >= uint64(cylinders)*uint64(heads) {
				return nil, fmt.Errorf("ckd_image: track number outside volume")
			}
			list, ok := item[1].(*starlark.List)
			if !ok {
				return nil, fmt.Errorf("ckd_image: tracks maps numbers to lists of (number, key, data) tuples")
			}
			if list.Len() > (trackSize-13)/8 {
				return nil, fmt.Errorf("ckd_image: record counts exceed track size")
			}
			used := 13
			var records []Record
			for i := 0; i < list.Len(); i++ {
				tuple, ok := list.Index(i).(starlark.Tuple)
				if !ok || len(tuple) != 3 {
					return nil, fmt.Errorf("ckd_image: expected (number, key, data) tuple")
				}
				n, err := starlark.AsInt32(tuple[0])
				key, kok := tuple[1].(starlark.Bytes)
				data, dok := tuple[2].(starlark.Bytes)
				if err != nil || n < 0 || n > 255 || !kok || !dok {
					return nil, fmt.Errorf("ckd_image: record requires a byte number and byte key/data")
				}
				if len(key) > 255 || len(data) > 65535 || len(key)+len(data)+8 > trackSize-used {
					return nil, fmt.Errorf("ckd_image: record exceeds key, data or track bounds")
				}
				used += 8 + len(key) + len(data)
				records = append(records, Record{Cylinder: uint16(t / heads), Head: uint16(t % heads), Number: byte(n), Key: []byte(key), Data: []byte(data)})
			}
			out[uint32(t)] = records
		}
	}
	img, err := BuildImage(uint32(cylinders), uint32(heads), uint32(trackSize), byte(device), out)
	if err != nil {
		return nil, err
	}
	return starfile.NewReader("volume.ckd", img), nil
}
