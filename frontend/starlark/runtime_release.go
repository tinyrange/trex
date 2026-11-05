package starlarkfrontend

import (
	"runtime/debug"

	"go.starlark.net/starlark"
)

// runtimeReleaseMemoryBuiltin is an explicit phase boundary, not an implicit
// side effect of stats or VM startup. The caller must first drop construction
// references. Reachable readers, caches and guest resources remain live.
func runtimeReleaseMemoryBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("runtime.release_memory", args, kwargs); err != nil {
		return nil, err
	}
	if _, err := resourcesForThread(thread); err != nil {
		return nil, err
	}
	debug.FreeOSMemory()
	return starlark.None, nil
}
