package starlarkfrontend

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestDigestManyCallerPlanningOverlapsAndAlwaysJoins(t *testing.T) {
	for _, failCallback := range []bool{false, true} {
		entered := make(chan struct{}, 8)
		release := make(chan struct{})
		var active, peak atomic.Int32
		original := starfile.NewReader("source", &digestTestReader{started: entered, release: release, active: &active, peak: &peak, size: 8})
		inputs := starlark.NewList([]starlark.Value{original, original})
		thread := &starlark.Thread{Name: "planning"}
		failure := errors.New("read-only planning rejected input")
		calls := 0
		callback := starlark.NewBuiltin("plan", func(gotThread *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
			calls++
			if gotThread != thread {
				t.Error("callback used another interpreter thread")
			}
			for i := 0; i < 2; i++ {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					close(release)
					return nil, errors.New("reader did not overlap caller")
				}
			}
			// Captured reader membership must not follow caller-list changes.
			if err := inputs.SetIndex(0, starlark.Bytes("replacement")); err != nil {
				t.Error(err)
			}
			close(release)
			if failCallback {
				return nil, failure
			}
			return starlark.None, nil
		})
		got, err := digestManyBuiltin(thread, nil, starlark.Tuple{inputs}, []starlark.Tuple{{starlark.String("while_running"), callback}})
		if calls != 1 || active.Load() != 0 {
			t.Fatal("callback repeated or workers leaked", calls, active.Load())
		}
		if failCallback {
			if got != nil || !errors.Is(err, failure) {
				t.Fatal("lost callback failure", got, err)
			}
		} else {
			want, e := digestBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("contents")}, nil)
			if err != nil || e != nil || got.(*starlark.List).Index(0) != want || got.(*starlark.List).Index(1) != want {
				t.Fatal("captured input changed", got, err)
			}
		}
	}
}
