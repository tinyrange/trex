package starlarkfrontend

import (
	"fmt"
	"go.starlark.net/starlark"
	"runtime/debug"
)

// Explicit process policy, never an implicit side effect of starting a VM.
func runtimeSetMemoryLimitBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var limit int64
	if err := starlark.UnpackArgs("runtime.set_memory_limit", args, kwargs, "bytes", &limit); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, fmt.Errorf("runtime.set_memory_limit: bytes must be positive")
	}
	if _, err := resourcesForThread(thread); err != nil {
		return nil, err
	}
	return starlark.MakeInt64(debug.SetMemoryLimit(limit)), nil
}
