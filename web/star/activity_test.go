package star

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"go.starlark.net/starlark"
)

// A long handler must not block progress observation, and its print() output
// must reach the activity log while it is still running.
func TestActivityObservesLongHandlerWithoutItsMutex(t *testing.T) {
	release := make(chan struct{})
	handler := starlark.NewBuiltin("handle", func(thread *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		thread.Print(thread, "constructing media")
		<-release
		return starlark.String("ok"), nil
	})
	app := NewApplication(&starlark.Thread{Print: func(*starlark.Thread, string) {}}, handler)
	done := make(chan struct{})
	go func() { defer close(done); app.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/boot", nil)) }()
	read := func(query string) activitySnapshot {
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, httptest.NewRequest("GET", ActivityPath+query, nil))
		var s activitySnapshot
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &s) != nil {
			t.Fatal(rec.Code, rec.Body.String())
		}
		return s
	}
	s := read("?after=0&wait=2")
	for s.Route == "" || len(s.Lines) == 0 { // the print may land before or after the busy transition
		s = read("?after=0&wait=2&busy=" + s.Route)
	}
	if !s.Busy || s.Route != "/api/boot" || s.Lines[0].Text != "constructing media" || s.Next != 2 {
		t.Fatalf("unexpected activity %+v", s)
	}
	started := time.Now()
	waiting := make(chan activitySnapshot)
	go func() { waiting <- read("?after=1&wait=5&busy=/api/boot") }()
	time.Sleep(20 * time.Millisecond)
	close(release)
	<-done
	s = <-waiting
	if s.Busy || len(s.Lines) != 0 || time.Since(started) > 2*time.Second {
		t.Fatalf("long poll did not end on completion: %+v after %v", s, time.Since(started))
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest("POST", ActivityPath, nil))
	if rec.Code != 405 {
		t.Fatal("activity accepted a mutation", rec.Code)
	}
}
