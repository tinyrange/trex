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

func etlReportBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 4_000_000
	if err := starlark.UnpackArgs("etl_report", args, kwargs, "file", &value, "max_events?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("etl_report: want file, got %s", value.Type())
	}
	if maximum < 1 || maximum > 4_000_000 {
		return nil, fmt.Errorf("etl_report: max_events must be 1..4000000")
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	report, err := etl.Analyze(resources.Context(), file, file.Size(), etl.Limits{MaxEvents: maximum})
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	return starlark.Call(thread, starjson.Module.Members["decode"], starlark.Tuple{starlark.String(data)}, nil)
}
