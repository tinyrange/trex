package sharedmime

import (
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func CompileBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("shared_mime_info", args, kwargs, "xml", &value); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok || source.Size() < 0 || source.Size() > 16<<20 {
		return nil, fmt.Errorf("shared_mime_info: expected an XML file of at most 16 MiB")
	}
	files, err := Compile(io.NewSectionReader(source, 0, source.Size()))
	if err != nil {
		return nil, err
	}
	result := starlark.NewDict(len(files))
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if err := result.SetKey(starlark.String(name), &starfile.Bytes{Name: name, Data: files[name]}); err != nil {
			return nil, err
		}
	}
	return result, nil
}
