package windows

import (
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/dmr"
	"go.starlark.net/starlark"
)

// dmrSectionsBuiltin exposes the native envelope reader without interpreting
// unknown section payloads or claiming that a graph is complete for activation.
func dmrSectionsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	limit := int64(64 << 20)
	if err := starlark.UnpackArgs("dmr_sections", args, kwargs, "file", &value, "max_bytes?", &limit); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("dmr_sections: expected file")
	}
	if limit < 36 || limit > 1<<30 || file.Size() < 36 || file.Size() > limit {
		return nil, fmt.Errorf("dmr_sections: invalid extent or byte limit")
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("dmr_sections: read exceeds byte limit")
	}
	sections, err := dmr.ParseContainer(data)
	if err != nil {
		return nil, err
	}
	result := make([]starlark.Value, len(sections))
	for i, section := range sections {
		row := starlark.NewDict(2)
		if err := row.SetKey(starlark.String("tag"), starlark.MakeUint(uint(section.Tag))); err != nil {
			return nil, err
		}
		if err := row.SetKey(starlark.String("data"), &starfile.Bytes{Data: section.Data}); err != nil {
			return nil, err
		}
		result[i] = row
	}
	return starlark.NewList(result), nil
}
