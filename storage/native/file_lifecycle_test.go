package native

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tinyrange/trex/lifecycle"
	"go.starlark.net/starlark"
)

func TestOpenFileOwnedByExecution(t *testing.T) {
	name := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(name, []byte("source bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	thread := &starlark.Thread{}
	resources := lifecycle.Install(thread)
	t.Cleanup(func() { _ = resources.Close() })
	value, err := openBuiltin(thread, nil, starlark.Tuple{starlark.String(name)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	file := value.(*osFile)
	sliceMethod, _ := file.Attr("slice")
	slice, err := starlark.Call(thread, sliceMethod, starlark.Tuple{starlark.MakeInt(1), starlark.MakeInt(3)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	view := slice.(File)
	data := make([]byte, 3)
	if _, err := view.ReadAt(data, 0); err != nil || string(data) != "our" {
		t.Fatalf("borrowed view: %q %v", data, err)
	}
	if err := resources.Close(); err != nil {
		t.Fatal(err)
	}
	for _, reader := range []File{file, view} {
		if _, err := reader.ReadAt(data, 0); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("read after execution closed: %v", err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := resources.Close(); err != nil {
		t.Fatal(err)
	}
	// A closed execution must not acquire another input handle.
	if v, err := openBuiltin(thread, nil, starlark.Tuple{starlark.String(name)}, nil); !errors.Is(err, context.Canceled) || v != nil {
		t.Fatalf("open after close: %v %v", v, err)
	}
}
