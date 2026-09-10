package windows

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/dmr"
	"go.starlark.net/starlark"
)

func dmrAlternatePathBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	family := false
	if err := starlark.UnpackArgs("dmr_alternate_path", args, kwargs, "value", &path, "first_package_family?", &family); err != nil {
		return nil, err
	}
	data, err := dmr.EncodeAlternatePath(path, family)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: data}, nil
}

func dmrMutablePathsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var values *starlark.List
	if err := starlark.UnpackArgs("dmr_mutable_paths", args, kwargs, "paths", &values); err != nil {
		return nil, err
	}
	if values.Len() < 1 || values.Len() > 641 {
		return nil, fmt.Errorf("dmr_mutable_paths: count must be 1..641")
	}
	paths := make([]string, values.Len())
	for i := range paths {
		var ok bool
		paths[i], ok = starlark.AsString(values.Index(i))
		if !ok {
			return nil, fmt.Errorf("dmr_mutable_paths: expected string at %d", i)
		}
	}
	data, err := dmr.EncodeMutablePaths(paths)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: data}, nil
}

func dmrTrailerBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("dmr_trailer", args, kwargs); err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: dmr.EncodeTrailer()}, nil
}

// dmrContainerBuiltin combines ordered section files without choosing required
// sections or treating an envelope as proof of a valid Windows package graph.
func dmrContainerBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var values *starlark.List
	limit := int64(64 << 20)
	if err := starlark.UnpackArgs("dmr_container", args, kwargs, "sections", &values, "max_bytes?", &limit); err != nil {
		return nil, err
	}
	if values.Len() < 1 || values.Len() > 8192 {
		return nil, fmt.Errorf("dmr_container: count must be 1..8192")
	}
	size := int64(28 + 8*values.Len())
	if limit < size || limit > 1<<30 {
		return nil, fmt.Errorf("dmr_container: invalid byte limit")
	}
	sections := make([]dmr.Section, values.Len())
	for i := range sections {
		file, ok := values.Index(i).(starfile.File)
		if !ok {
			return nil, fmt.Errorf("dmr_container: section %d must be a file", i)
		}
		if file.Size() < 4 || file.Size()%4 != 0 || file.Size() > limit-size {
			return nil, fmt.Errorf("dmr_container: section %d exceeds extent/byte limit", i)
		}
		data, err := starfile.ReadAll(file)
		if err != nil {
			return nil, err
		}
		if len(data) < 4 || len(data)%4 != 0 || int64(len(data)) > limit-size {
			return nil, fmt.Errorf("dmr_container: invalid section bytes")
		}
		size += int64(len(data))
		sections[i] = dmr.Section{Tag: binary.LittleEndian.Uint32(data), Data: data}
	}
	data, err := dmr.EncodeContainer(sections)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: data}, nil
}
