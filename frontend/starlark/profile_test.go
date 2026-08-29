package starlarkfrontend

import (
	"testing"
	"time"

	"go.starlark.net/starlark"
)

type testMonotonicClock struct {
	now time.Duration
}

func (c *testMonotonicClock) Now() time.Duration { return c.now }

func TestProfilerRecordsNestedSpansAndCounters(t *testing.T) {
	clock := &testMonotonicClock{now: time.Second}
	profile := &starlarkProfiler{clock: clock, started: clock.Now(), counters: make(map[string]int64)}
	outer := profile.startSpan("build")
	clock.now += 2 * time.Millisecond
	inner := profile.startSpan("registry")
	clock.now += 3 * time.Millisecond
	if _, err := profile.finishSpan(outer.id); err == nil {
		t.Fatal("ending an outer span before its child succeeded")
	}
	if _, err := profile.finishSpan(inner.id); err != nil {
		t.Fatal(err)
	}
	clock.now += time.Millisecond
	if _, err := profile.finishSpan(outer.id); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.counterBuiltin(nil, nil, starlark.Tuple{starlark.String("files"), starlark.MakeInt(7)}, nil); err != nil {
		t.Fatal(err)
	}

	value, err := profile.snapshotBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := value.(*starlarkRecord)
	spans := snapshot.Values["spans"].(*starlark.List)
	if spans.Len() != 2 {
		t.Fatalf("span count = %d, want 2", spans.Len())
	}
	outerRecord := spans.Index(0).(*starlarkRecord)
	innerRecord := spans.Index(1).(*starlarkRecord)
	if got, _ := outerRecord.Values["duration_ns"].(starlark.Int).Int64(); got != int64(6*time.Millisecond) {
		t.Fatalf("outer duration = %d ns", got)
	}
	parent, _ := innerRecord.Values["parent"].(starlark.Int).Uint64()
	if parent != outer.id {
		t.Fatalf("inner parent = %d, want %d", parent, outer.id)
	}
	counters := snapshot.Values["counters"].(*starlark.Dict)
	files, found, err := counters.Get(starlark.String("files"))
	if err != nil || !found || files.String() != "7" {
		t.Fatalf("files counter = %v, %v, %v", files, found, err)
	}
}

func TestClockMonotonicUsesRuntimeClock(t *testing.T) {
	thread := &starlark.Thread{Name: "clock-test"}
	thread.SetLocal(runtimeClockKey, monotonicClock(&testMonotonicClock{now: 1500 * time.Millisecond}))
	value, err := clockMonotonicBuiltin(thread, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := float64(value.(starlark.Float)); got != 1.5 {
		t.Fatalf("clock.monotonic() = %g, want 1.5", got)
	}
}

func TestProfilerReportEnforcesCoverageAndIncludesRuntimeStats(t *testing.T) {
	clock := &testMonotonicClock{now: time.Second}
	thread := &starlark.Thread{Name: "profile-report-test"}
	thread.SetLocal(runtimeClockKey, monotonicClock(clock))
	resources := installRuntimeResources(thread)
	defer resources.Close()
	profile := &starlarkProfiler{clock: clock, started: clock.Now(), counters: make(map[string]int64)}
	span := profile.startSpan("build")
	clock.now += 95 * time.Millisecond
	if _, err := profile.finishSpan(span.id); err != nil {
		t.Fatal(err)
	}
	clock.now += 5 * time.Millisecond
	value, err := profile.reportBuiltin(thread, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	report := value.(*starlarkRecord)
	if report.Values["coverage_ppm"].String() != "950000" || report.Values["runtime"].Type() != "record" {
		t.Fatalf("profile report = %s", report)
	}
	if _, err := profile.reportBuiltin(thread, nil, nil, []starlark.Tuple{{starlark.String("minimum_coverage"), starlark.Float(0.96)}}); err == nil {
		t.Fatal("profile report accepted insufficient coverage")
	}
}
