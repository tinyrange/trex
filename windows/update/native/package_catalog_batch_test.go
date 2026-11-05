package native

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
	"testing"
)

func TestCatalogOverlapJoinsOnCallbackFailure(t *testing.T) {
	entered := make(chan struct{})
	resume := make(chan struct{})
	finished := make(chan struct{})
	callback := starlark.NewBuiltin("control", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		<-entered
		close(resume)
		return nil, fmt.Errorf("callback failure")
	})
	files, err := captureCatalogBatch(&starlark.Thread{}, callback, func() ([]storage.Reader, error) {
		close(entered)
		<-resume
		close(finished)
		return nil, fmt.Errorf("worker failure")
	})
	if files != nil || err == nil || err.Error() != "callback failure" {
		t.Fatalf("%v %v", files, err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("worker outlived callback")
	}
}
