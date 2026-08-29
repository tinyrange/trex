package installscript

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type File = starfile.File

func starlarkStringDict(values map[string]starlark.Value) *starlark.Dict {
	result := starlark.NewDict(len(values))
	for name, value := range values {
		_ = result.SetKey(starlark.String(name), value)
	}
	return result
}
