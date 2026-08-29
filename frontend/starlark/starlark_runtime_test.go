package starlarkfrontend

import (
	"testing"

	"go.starlark.net/starlark"
)

func callWindowsRuntime(t *testing.T, name string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	t.Helper()
	thread, environment, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	windows := environment["windows"].(namespace)
	value, found := windows.attrs[name]
	if !found {
		t.Fatalf("unknown Windows runtime export %q", name)
	}
	return starlark.Call(thread, value.(starlark.Callable), args, kwargs)
}
