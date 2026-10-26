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

// etlWalkBuiltin exposes validated raw records without retaining the trace.
func etlWalkBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var visit starlark.Callable
	maximum, group, opcode := 4_000_000, -1, -1
	var minTick, maxTick uint64
	if err := starlark.UnpackArgs("etl_walk", args, kwargs, "file", &value, "visit", &visit, "group?", &group, "opcode?", &opcode, "min_tick?", &minTick, "max_tick?", &maxTick, "max_events?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("etl_walk: want file, got %s", value.Type())
	}
	if maximum < 1 || maximum > 4_000_000 || group < -1 || group > 255 || opcode < -1 || opcode > 255 || (maxTick != 0 && maxTick < minTick) {
		return nil, fmt.Errorf("etl_walk: invalid limits or filters")
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	header, err := etl.Walk(resources.Context(), file, file.Size(), etl.Limits{MaxEvents: maximum}, func(e etl.Event) error {
		if (group >= 0 && int(e.Group) != group) || (opcode >= 0 && int(e.Opcode) != opcode) || e.Timestamp < minTick || (maxTick != 0 && e.Timestamp > maxTick) {
			return nil
		}
		record := starfile.NewRecord(starlark.StringDict{
			"provider_id": starlark.Bytes(string(e.ProviderID[:])), "event_id": starlark.MakeInt(int(e.EventID)),
			"marker": starlark.MakeInt(int(e.Marker)), "message_flags": starlark.MakeInt(int(e.MessageFlags)),
			"offset": starlark.MakeInt64(e.Offset), "tick": starlark.MakeUint64(e.Timestamp),
			"cpu": starlark.MakeInt(int(e.CPU)), "header_type": starlark.MakeInt(int(e.HeaderType)),
			"group": starlark.MakeInt(int(e.Group)), "opcode": starlark.MakeInt(int(e.Opcode)), "version": starlark.MakeInt(int(e.Version)),
			"pid": starlark.MakeUint64(uint64(e.PID)), "tid": starlark.MakeUint64(uint64(e.TID)), "payload": starlark.Bytes(string(e.Payload)),
		})
		_, err := starlark.Call(thread, visit, starlark.Tuple{record}, nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	return starlark.Call(thread, starjson.Module.Members["decode"], starlark.Tuple{starlark.String(data)}, nil)
}
