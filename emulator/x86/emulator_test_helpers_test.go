package x86

import (
	"testing"

	windowsapi "github.com/tinyrange/trex/windows"
	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

func starlarkFileOptions() *syntax.FileOptions {
	return &syntax.FileOptions{Set: true, While: true, TopLevelControl: true, GlobalReassign: true, Recursion: true}
}

func peFixupValue(t *testing.T, offset int, label string) *starlark.Dict {
	t.Helper()
	fixup := starlark.NewDict(2)
	_ = fixup.SetKey(starlark.String("offset"), starlark.MakeInt(offset))
	_ = fixup.SetKey(starlark.String("label"), starlark.String(label))
	return fixup
}

func callWindowsRuntime(t *testing.T, name string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	t.Helper()
	builtin, ok := windowsapi.Builtins()[name]
	if !ok {
		t.Fatalf("unknown Windows builtin %q", name)
	}
	return starlark.Call(&starlark.Thread{Name: "emulator test"}, builtin, args, kwargs)
}
