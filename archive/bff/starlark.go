package bff

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum, decoded := 1000000, int64(512<<20)
	if err := starlark.UnpackArgs("bff", args, kwargs, "file", &value, "maximum_entries?", &maximum, "maximum_decoded_bytes?", &decoded); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("bff: expected file")
	}
	a, err := Open(file, maximum, decoded)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, len(a.Entries))
	for i, e := range a.Entries {
		entries[i] = starfile.NewRecord(starlark.StringDict{
			"path": starlark.String(e.Path), "name": starlark.Bytes(e.Name), "entry_type": starlark.String(e.Kind), "offset": starlark.MakeInt64(e.Offset),
			"inode": starlark.MakeUint(uint(e.Inode)), "mode": starlark.MakeUint(uint(e.Mode)), "uid": starlark.MakeUint(uint(e.UID)), "gid": starlark.MakeUint(uint(e.GID)), "links": starlark.MakeUint(uint(e.Links)),
			"accessed": starlark.MakeUint(uint(e.Accessed)), "modified": starlark.MakeUint(uint(e.Modified)), "changed": starlark.MakeUint(uint(e.Changed)),
			"device_major": starlark.MakeUint(uint(e.DeviceMajor)), "device_minor": starlark.MakeUint(uint(e.DeviceMinor)), "special_major": starlark.MakeUint(uint(e.SpecialMajor)), "special_minor": starlark.MakeUint(uint(e.SpecialMinor)),
			"packed": starlark.Bool(e.Packed), "header": e.Header, "acl": e.ACL, "pcl": e.PCL, "stored_data": e.Stored, "stored_size": starlark.MakeInt64(e.Stored.Size()), "data": e.Data, "size": starlark.MakeInt64(e.Data.Size()),
		})
	}
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(entries), "header": a.Header, "trailer": a.Trailer, "volume": starlark.MakeUint(uint(a.Volume)), "date": starlark.MakeUint(uint(a.Date)), "previous_date": starlark.MakeUint(uint(a.PreviousDate)), "volume_words": starlark.MakeUint(uint(a.VolumeWords)), "disk": starlark.Bytes(a.Disk), "filesystem": starlark.Bytes(a.Filesystem), "user": starlark.Bytes(a.User)}), nil
}
