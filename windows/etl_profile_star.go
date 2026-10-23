package windows

import (
	"encoding/json"
	"fmt"
	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/etl"
	starjson "go.starlark.net/lib/json"
	"go.starlark.net/starlark"
)

func etlProfileBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	if err := starlark.UnpackArgs("etl_profile", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	if file == nil {
		return nil, fmt.Errorf("etl_profile: expected file")
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	profile, err := etl.ProfileTrace(resources.Context(), file, file.Size(), etl.Limits{})
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	return starlark.Call(thread, starjson.Module.Members["decode"], starlark.Tuple{starlark.String(b)}, nil)
}
