package windows

import (
	"encoding/binary"
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// defenderDefinitionMetadata reads only the inspected RMDX header layout.
// In native Defender's signature-selection state, the *SignatureApplied fields
// contain this source generation time, not the installation time or a trust
// verdict. No clock, payload decompression or signature verification is used.
func defenderDefinitionMetadata(resources []peResource) (starlark.Value, error) {
	var data []byte
	found := false
	for _, resource := range resources {
		if (resource.typ != "#10" && resource.typ != "RT_RCDATA") || resource.name != "#1000" {
			continue
		}
		if found {
			return nil, fmt.Errorf("defender_definition: ambiguous RMDX resource")
		}
		found = true
		data = resource.data
	}
	if !found {
		return starlark.None, nil
	}
	if len(data) < 32 || string(data[:4]) != "RMDX" {
		return nil, fmt.Errorf("defender_definition: missing or truncated RMDX header")
	}
	if binary.LittleEndian.Uint32(data[8:12]) != 0xffffffff ||
		binary.LittleEndian.Uint32(data[12:16]) != 0x00200002 ||
		binary.LittleEndian.Uint64(data[16:24]) != 0 {
		return nil, fmt.Errorf("defender_definition: unsupported RMDX header layout")
	}
	created := binary.LittleEndian.Uint32(data[4:8])
	offset := binary.LittleEndian.Uint32(data[24:28])
	if created == 0 || created == 0xffffffff || offset < 32 || uint64(offset) >= uint64(len(data)) || binary.LittleEndian.Uint32(data[28:32]) == 0 {
		return nil, fmt.Errorf("defender_definition: invalid generation time or payload bounds")
	}
	out := starlark.NewDict(2)
	_ = out.SetKey(starlark.String("created_unix"), starlark.MakeUint64(uint64(created)))
	_ = out.SetKey(starlark.String("created_filetime"), starlark.MakeUint64(116444736000000000+uint64(created)*10000000))
	return out, nil
}

func peDefenderDefinitionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	if err := starlark.UnpackArgs("defender_definition", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	data, err := peReadSnapshotData(file)
	if err != nil {
		return nil, err
	}
	resources, err := peResources(data)
	if err != nil {
		return nil, err
	}
	return defenderDefinitionMetadata(resources)
}
