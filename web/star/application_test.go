package star

import (
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tinyrange/trex/auto"
	autostar "github.com/tinyrange/trex/auto/star"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestScriptedApplicationSharesExecutionMutex(t *testing.T) {
	mu := &sync.Mutex{}
	entered := make(chan struct{})
	handler := starlark.NewBuiltin("handle", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		close(entered)
		return starlark.String("ok"), nil
	})
	app := NewApplicationWithMutex(&starlark.Thread{}, handler, mu)
	mu.Lock()
	done := make(chan struct{})
	go func() { defer close(done); app.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil)) }()
	select {
	case <-entered:
		t.Fatal("handler entered while workspace owns recipe thread")
	case <-time.After(20 * time.Millisecond):
	}
	mu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not resume")
	}
}
func TestBrowseMountedPathAndTraversal(t *testing.T) {
	root := auto.FromView(auto.ViewFunc(func() ([]auto.Entry, error) {
		return []auto.Entry{{Name: "sample.txt", Kind: "file", Reader: &starfile.Bytes{Data: []byte("original")}}}, nil
	}), "Archive", auto.Options{})
	route := "/sample.txt"
	app := NewApplication(&starlark.Thread{}, starlark.NewBuiltin("handle", func(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		return webBrowseBuiltin(thread, builtin, starlark.Tuple{&autostar.Value{Node: root}, args[0]}, []starlark.Tuple{{starlark.String("path"), starlark.String(route)}})
	}))
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest("GET", "/api/archive/sample.txt", nil))
	if rec.Code != 200 || rec.Body.String() != "original" {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Security-Policy") != "sandbox" {
		t.Fatal("raw archived files not sandboxed")
	}
	route = "/../sample.txt"
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest("GET", "/api/archive/anything?json=1", nil))
	if rec.Code != 400 {
		t.Fatal(rec.Code, rec.Body.String())
	}
}
