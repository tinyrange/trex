package starlarkfrontend

import (
	"go.starlark.net/starlark"
	"runtime/debug"
	"testing"
)

func TestRuntimeMemoryLimitExplicitValidationAndRestore(t *testing.T) {
	thread := &starlark.Thread{Name: "memory-limit"}
	resources := installRuntimeResources(thread)
	defer resources.Close()
	previous := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(previous)
	for _, n := range []int64{0, -1} {
		if _, err := runtimeSetMemoryLimitBuiltin(thread, nil, starlark.Tuple{starlark.MakeInt64(n)}, nil); err == nil {
			t.Fatal("accepted nonpositive limit")
		}
		if debug.SetMemoryLimit(-1) != previous {
			t.Fatal("invalid call mutated policy")
		}
	}
	const budget = 1 << 30
	old, err := runtimeSetMemoryLimitBuiltin(thread, nil, starlark.Tuple{starlark.MakeInt64(budget)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := old.(starlark.Int).Int64()
	if got != previous || debug.SetMemoryLimit(-1) != budget {
		t.Fatal("previous/new budget mismatch")
	}
	if _, err := runtimeSetMemoryLimitBuiltin(thread, nil, starlark.Tuple{old}, nil); err != nil {
		t.Fatal(err)
	}
	if debug.SetMemoryLimit(-1) != previous {
		t.Fatal("restore failed")
	}
}
