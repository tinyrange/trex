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

func etlSchedulerBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var pid uint32
	maximum, records := 4000000, 200000
	if err := starlark.UnpackArgs("etl_scheduler", args, kwargs, "file", &value, "pid", &pid, "max_events?", &maximum, "max_records?", &records); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("etl_scheduler: expected file")
	}
	if maximum < 1 || maximum > 4000000 {
		return nil, fmt.Errorf("etl_scheduler: max_events must be 1..4000000")
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	result, err := etl.SchedulerTrace(resources.Context(), file, file.Size(), etl.Limits{MaxEvents: maximum}, pid, records)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return starlark.Call(thread, starjson.Module.Members["decode"], starlark.Tuple{starlark.String(data)}, nil)
}
