package starlarkfrontend

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"math"
	"time"
)

func clockReadProfilerBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	files, events, minimum := 16384, 1024, 0.01
	if err := starlark.UnpackArgs("read_profiler", args, kwargs, "max_files?", &files, "max_events?", &events, "min_seconds?", &minimum); err != nil {
		return nil, err
	}
	if math.IsNaN(minimum) || math.IsInf(minimum, 0) || minimum < 0 || minimum > 86400 {
		return nil, fmt.Errorf("read_profiler: min_seconds must be finite and within 0..86400")
	}
	clock, err := clockForThread(thread)
	if err != nil {
		return nil, err
	}
	p, err := storage.NewReadProfiler(clock, files, events, time.Duration(minimum*float64(time.Second)))
	if err != nil {
		return nil, err
	}
	return &readProfilerValue{p}, nil
}

type readProfilerValue struct{ profile *storage.ReadProfiler }

func (*readProfilerValue) String() string        { return "<read profiler>" }
func (*readProfilerValue) Type() string          { return "clock.read_profiler" }
func (*readProfilerValue) Freeze()               {}
func (*readProfilerValue) Truth() starlark.Bool  { return starlark.True }
func (*readProfilerValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: read profiler") }
func (*readProfilerValue) AttrNames() []string   { return []string{"file", "reset", "snapshot"} }
func (v *readProfilerValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "file":
		return starlark.NewBuiltin("read_profiler.file", v.file), nil
	case "reset":
		return starlark.NewBuiltin("read_profiler.reset", v.reset), nil
	case "snapshot":
		return starlark.NewBuiltin("read_profiler.snapshot", v.snapshot), nil
	}
	return nil, nil
}
func (v *readProfilerValue) file(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var label string
	if err := starlark.UnpackArgs("read_profiler.file", args, kwargs, "source", &value, "label", &label); err != nil {
		return nil, err
	}
	var source storage.Reader
	switch f := value.(type) {
	case storage.Reader:
		source = f
	case starlark.Bytes:
		source = &starfile.Bytes{Data: []byte(f)}
	case starlark.String:
		source = &starfile.Bytes{Data: []byte(f)}
	default:
		return nil, fmt.Errorf("read_profiler.file: expected file, bytes or string")
	}
	reader, err := v.profile.Wrap(source, label)
	if err != nil {
		return nil, err
	}
	return starfile.NewReader(label, reader), nil
}
func (v *readProfilerValue) reset(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("read_profiler.reset", args, kwargs); err != nil {
		return nil, err
	}
	v.profile.Reset()
	return starlark.None, nil
}
func profileDict(values starlark.StringDict) *starlark.Dict {
	d := starlark.NewDict(len(values))
	for k, v := range values {
		_ = d.SetKey(starlark.String(k), v)
	}
	return d
}
func readStatValue(s storage.ReadStat) *starlark.Dict {
	return profileDict(starlark.StringDict{"label": starlark.String(s.Label), "calls": starlark.MakeInt64(s.Calls), "requested_bytes": starlark.MakeInt64(s.Requested), "bytes": starlark.MakeInt64(s.Bytes), "errors": starlark.MakeInt64(s.Errors), "total_seconds": starlark.Float(s.Total.Seconds()), "max_seconds": starlark.Float(s.Max.Seconds())})
}
func (v *readProfilerValue) snapshot(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	limit := 100
	if err := starlark.UnpackArgs("read_profiler.snapshot", args, kwargs, "limit?", &limit); err != nil {
		return nil, err
	}
	if limit < 0 {
		return nil, fmt.Errorf("read_profiler.snapshot: limit must be nonnegative")
	}
	s := v.profile.Snapshot(limit)
	files, events := make([]starlark.Value, 0, len(s.Files)), make([]starlark.Value, 0, len(s.Events))
	for _, f := range s.Files {
		files = append(files, readStatValue(f))
	}
	for _, e := range s.Events {
		events = append(events, profileDict(starlark.StringDict{"label": starlark.String(e.Label), "offset": starlark.MakeInt64(e.Offset), "requested_bytes": starlark.MakeInt(e.Requested), "bytes": starlark.MakeInt(e.Bytes), "started_seconds": starlark.Float(e.Started.Seconds()), "duration_seconds": starlark.Float(e.Duration.Seconds()), "error": starlark.String(e.Error)}))
	}
	return profileDict(starlark.StringDict{"elapsed_seconds": starlark.Float(s.Elapsed.Seconds()), "total": readStatValue(s.Total), "files": starlark.NewList(files), "slowest_reads": starlark.NewList(events), "tracked_files": starlark.MakeInt(s.TrackedFiles), "unattributed_calls": starlark.MakeInt64(s.Unattributed), "slow_reads": starlark.MakeInt64(s.SlowReads), "omitted_slow_reads": starlark.MakeInt64(s.SlowReads - int64(len(s.Events)))}), nil
}
