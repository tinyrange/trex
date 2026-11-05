package native

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.starlark.net/starlark"
)

func TestMediaPreparationOverlapJoinsAndPublishes(t *testing.T) {
	for _, mode := range []string{"success", "worker error", "callback error"} {
		t.Run(mode, func(t *testing.T) {
			started, callbackDone, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var callbackActive atomic.Bool
			var callbackCalls, workerCalls atomic.Int32
			workerError := errors.New("native preparation failed")
			callbackError := errors.New("baseline failed")
			var logs []string
			thread := &starlark.Thread{}
			// Use the original caller thread, never a fabricated worker thread.
			thread.Print = func(got *starlark.Thread, message string) {
				if got != thread || callbackActive.Load() {
					t.Error("invalid caller-thread diagnostic")
				}
				logs = append(logs, message)
			}
			callback := starlark.NewBuiltin("baseline", func(got *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				callbackCalls.Add(1)
				if got != thread || len(args) != 0 || len(kwargs) != 0 {
					t.Error("wrong callback invocation")
				}
				callbackActive.Store(true)
				<-started
				callbackActive.Store(false)
				close(callbackDone)
				if mode == "callback error" {
					return nil, callbackError
				}
				return starlark.String("ignored"), nil
			})
			var value starlark.Value
			var err error
			var retainedObserver func(string)
			go func() {
				defer close(returned)
				value, err = runMediaPreparation(thread, callback, func(observe func(string)) (starlark.Value, error) {
					workerCalls.Add(1)
					retainedObserver = observe
					observe("native progress")
					close(started)
					<-release
					if mode == "worker error" {
						return nil, workerError
					}
					return starlark.String("prepared"), nil
				})
			}()
			select {
			case <-callbackDone:
			case <-time.After(5 * time.Second):
				t.Fatal("no overlap")
			}
			select {
			case <-returned:
				t.Fatal("returned before joining native work")
			default:
			}
			close(release)
			select {
			case <-returned:
			case <-time.After(5 * time.Second):
				t.Fatal("join did not finish")
			}
			if callbackCalls.Load() != 1 || workerCalls.Load() != 1 {
				t.Fatal("work repeated")
			}
			if mode == "success" {
				if err != nil || value != starlark.String("prepared") {
					t.Fatalf("result %v, %v", value, err)
				}
			} else {
				expected := workerError
				if mode == "callback error" {
					expected = callbackError
				}
				if value != nil || !errors.Is(err, expected) {
					t.Fatalf("partial result %v, %v", value, err)
				}
			}
			if len(logs) != 1 || logs[0] != "native progress" {
				t.Fatalf("diagnostics %v", logs)
			}
			retainedObserver("late lazy read")
			if len(logs) != 1 {
				t.Fatal("retained reader touched old thread")
			}
		})
	}
}

func TestMediaPreparationBoundsDiagnostics(t *testing.T) {
	logs := 0
	thread := &starlark.Thread{Print: func(*starlark.Thread, string) { logs++ }}
	callback := starlark.NewBuiltin("baseline", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		return starlark.None, nil
	})
	_, err := runMediaPreparation(thread, callback, func(observe func(string)) (starlark.Value, error) {
		for i := 0; i < 2048; i++ {
			observe("progress")
		}
		return starlark.True, nil
	})
	if err != nil || logs != 1025 {
		t.Fatalf("logs=%d error=%v", logs, err)
	}
}
