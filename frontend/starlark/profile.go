package starlarkfrontend

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"go.starlark.net/starlark"
)

const runtimeClockKey = "trex.runtime.clock"

type monotonicClock interface {
	Now() time.Duration
}

type nativeMonotonicClock struct {
	started time.Time
}

func (c *nativeMonotonicClock) Now() time.Duration { return time.Since(c.started) }

func installRuntimeClock(thread *starlark.Thread) {
	thread.SetLocal(runtimeClockKey, monotonicClock(&nativeMonotonicClock{started: time.Now()}))
}

func clockForThread(thread *starlark.Thread) (monotonicClock, error) {
	if thread == nil {
		return nil, fmt.Errorf("clock: Starlark runtime is unavailable")
	}
	clock, ok := thread.Local(runtimeClockKey).(monotonicClock)
	if !ok || clock == nil {
		return nil, fmt.Errorf("clock: monotonic clock is unavailable")
	}
	return clock, nil
}

func clockMonotonicBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("monotonic", args, kwargs); err != nil {
		return nil, err
	}
	clock, err := clockForThread(thread)
	if err != nil {
		return nil, err
	}
	return starlark.Float(clock.Now().Seconds()), nil
}

func clockProfilerBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("profiler", args, kwargs); err != nil {
		return nil, err
	}
	clock, err := clockForThread(thread)
	if err != nil {
		return nil, err
	}
	return &starlarkProfiler{clock: clock, started: clock.Now(), counters: make(map[string]int64)}, nil
}

type profileSpanRecord struct {
	id       uint64
	name     string
	parent   uint64
	started  time.Duration
	duration time.Duration
	finished bool
}

type starlarkProfiler struct {
	mu       sync.Mutex
	clock    monotonicClock
	started  time.Duration
	nextID   uint64
	stack    []uint64
	spans    []profileSpanRecord
	counters map[string]int64
}

func (p *starlarkProfiler) String() string       { return "<profiler>" }
func (p *starlarkProfiler) Type() string         { return "clock.profiler" }
func (p *starlarkProfiler) Freeze()              {}
func (p *starlarkProfiler) Truth() starlark.Bool { return starlark.True }
func (p *starlarkProfiler) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", p.Type())
}
func (p *starlarkProfiler) Attr(name string) (starlark.Value, error) {
	switch name {
	case "counter":
		return starlark.NewBuiltin("profiler.counter", p.counterBuiltin), nil
	case "measure":
		return starlark.NewBuiltin("profiler.measure", p.measureBuiltin), nil
	case "report":
		return starlark.NewBuiltin("profiler.report", p.reportBuiltin), nil
	case "snapshot":
		return starlark.NewBuiltin("profiler.snapshot", p.snapshotBuiltin), nil
	case "span":
		return starlark.NewBuiltin("profiler.span", p.spanBuiltin), nil
	}
	return nil, nil
}
func (p *starlarkProfiler) AttrNames() []string {
	return []string{"counter", "measure", "report", "snapshot", "span"}
}

func (p *starlarkProfiler) startSpan(name string) *starlarkProfileSpan {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextID++
	parent := uint64(0)
	if len(p.stack) > 0 {
		parent = p.stack[len(p.stack)-1]
	}
	p.spans = append(p.spans, profileSpanRecord{
		id: p.nextID, name: name, parent: parent, started: p.clock.Now(),
	})
	p.stack = append(p.stack, p.nextID)
	return &starlarkProfileSpan{profiler: p, id: p.nextID, name: name}
}

func (p *starlarkProfiler) finishSpan(id uint64) (time.Duration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for index := range p.spans {
		record := &p.spans[index]
		if record.id != id {
			continue
		}
		if record.finished {
			return record.duration, nil
		}
		if len(p.stack) == 0 || p.stack[len(p.stack)-1] != id {
			return 0, fmt.Errorf("profiler: span %q ended before its nested span", record.name)
		}
		record.duration = p.clock.Now() - record.started
		record.finished = true
		p.stack = p.stack[:len(p.stack)-1]
		return record.duration, nil
	}
	return 0, fmt.Errorf("profiler: unknown span %d", id)
}

func (p *starlarkProfiler) spanBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("profiler.span", args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	return p.startSpan(name), nil
}

func (p *starlarkProfiler) measureBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("profiler.measure: got %d positional arguments, want at least 2", len(args))
	}
	name, ok := starlark.AsString(args[0])
	if !ok {
		return nil, fmt.Errorf("profiler.measure: name is %s, want string", args[0].Type())
	}
	callable, ok := args[1].(starlark.Callable)
	if !ok {
		return nil, fmt.Errorf("profiler.measure: function is %s, want callable", args[1].Type())
	}
	span := p.startSpan(name)
	value, callErr := starlark.Call(thread, callable, args[2:], kwargs)
	_, finishErr := p.finishSpan(span.id)
	if callErr != nil {
		return nil, callErr
	}
	if finishErr != nil {
		return nil, finishErr
	}
	return value, nil
}

func (p *starlarkProfiler) counterBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	amount := int64(1)
	if err := starlark.UnpackArgs("profiler.counter", args, kwargs, "name", &name, "amount?", &amount); err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.counters[name] += amount
	value := p.counters[name]
	p.mu.Unlock()
	return starlark.MakeInt64(value), nil
}

func (p *starlarkProfiler) snapshotBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("profiler.snapshot", args, kwargs); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.snapshotLocked(), nil
}

func (p *starlarkProfiler) snapshotLocked() *starlarkRecord {
	spans := make([]starlark.Value, len(p.spans))
	type interval struct{ start, end time.Duration }
	intervals := make([]interval, 0, len(p.spans))
	for index, span := range p.spans {
		fields := starlark.StringDict{
			"duration_ns": starlark.MakeInt64(span.duration.Nanoseconds()),
			"finished":    starlark.Bool(span.finished),
			"id":          starlark.MakeUint64(span.id),
			"name":        starlark.String(span.name),
			"parent":      starlark.MakeUint64(span.parent),
			"started_ns":  starlark.MakeInt64((span.started - p.started).Nanoseconds()),
		}
		spans[index] = newStarlarkRecord(fields)
		if span.finished && span.duration > 0 {
			intervals = append(intervals, interval{start: span.started, end: span.started + span.duration})
		}
	}
	counters := starlark.NewDict(len(p.counters))
	for name, value := range p.counters {
		_ = counters.SetKey(starlark.String(name), starlark.MakeInt64(value))
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].start < intervals[j].start })
	covered := time.Duration(0)
	if len(intervals) > 0 {
		start, end := intervals[0].start, intervals[0].end
		for _, current := range intervals[1:] {
			if current.start <= end {
				if current.end > end {
					end = current.end
				}
				continue
			}
			covered += end - start
			start, end = current.start, current.end
		}
		covered += end - start
	}
	elapsed := p.clock.Now() - p.started
	coveragePPM := int64(0)
	if elapsed > 0 {
		coveragePPM = int64(covered) * 1_000_000 / int64(elapsed)
	}
	return newStarlarkRecord(starlark.StringDict{
		"coverage_ppm": starlark.MakeInt64(coveragePPM),
		"covered_ns":   starlark.MakeInt64(covered.Nanoseconds()),
		"counters":     counters,
		"elapsed_ns":   starlark.MakeInt64(elapsed.Nanoseconds()),
		"spans":        starlark.NewList(spans),
	})
}

func (p *starlarkProfiler) reportBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	minimum := starlarkNumber(0.95)
	if err := starlark.UnpackArgs("profiler.report", args, kwargs, "minimum_coverage?", &minimum); err != nil {
		return nil, err
	}
	if minimum < 0 || minimum > 1 {
		return nil, fmt.Errorf("profiler.report: minimum_coverage must be between 0 and 1")
	}
	p.mu.Lock()
	if len(p.stack) != 0 {
		p.mu.Unlock()
		return nil, fmt.Errorf("profiler.report: %d spans are still active", len(p.stack))
	}
	snapshot := p.snapshotLocked()
	coverageValue := snapshot.Values["coverage_ppm"].(starlark.Int)
	coverage, _ := coverageValue.Int64()
	p.mu.Unlock()
	if coverage < int64(float64(minimum)*1_000_000) {
		return nil, fmt.Errorf("profiler.report: %.2f%% coverage is below %.2f%%", float64(coverage)/10_000, float64(minimum)*100)
	}
	runtimeStats, err := runtimeStatsBuiltin(thread, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	return newStarlarkRecord(starlark.StringDict{
		"coverage_ppm": snapshot.Values["coverage_ppm"],
		"covered_ns":   snapshot.Values["covered_ns"],
		"counters":     snapshot.Values["counters"],
		"elapsed_ns":   snapshot.Values["elapsed_ns"],
		"runtime":      runtimeStats,
		"spans":        snapshot.Values["spans"],
	}), nil
}

type starlarkProfileSpan struct {
	profiler *starlarkProfiler
	id       uint64
	name     string
}

func (s *starlarkProfileSpan) String() string       { return fmt.Sprintf("<profile.span %q>", s.name) }
func (s *starlarkProfileSpan) Type() string         { return "clock.span" }
func (s *starlarkProfileSpan) Freeze()              {}
func (s *starlarkProfileSpan) Truth() starlark.Bool { return starlark.True }
func (s *starlarkProfileSpan) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", s.Type())
}
func (s *starlarkProfileSpan) Attr(name string) (starlark.Value, error) {
	if name == "end" {
		return starlark.NewBuiltin("span.end", s.endBuiltin), nil
	}
	return nil, nil
}
func (s *starlarkProfileSpan) AttrNames() []string { return []string{"end"} }

func (s *starlarkProfileSpan) endBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("span.end", args, kwargs); err != nil {
		return nil, err
	}
	duration, err := s.profiler.finishSpan(s.id)
	if err != nil {
		return nil, err
	}
	return starlark.Float(duration.Seconds()), nil
}
