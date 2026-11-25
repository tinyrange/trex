package star

import (
	"fmt"
	"sync"

	"go.starlark.net/starlark"
)

func vmmCohortBuiltin(operation string) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		name := operation + "_many"
		var list *starlark.List
		if err := starlark.UnpackArgs(name, args, kwargs, "sessions", &list); err != nil {
			return nil, err
		}
		sessions := make([]*vmmSessionValue, list.Len())
		seen := make(map[*vmmSessionValue]bool, len(sessions))
		for index := range sessions {
			session, ok := list.Index(index).(*vmmSessionValue)
			if !ok || seen[session] {
				return nil, fmt.Errorf("%s expects distinct VM sessions (entry %d)", name, index)
			}
			if operation == "resume" {
				if _, ok := session.driver.(vmmControlDriver); !ok {
					return nil, unsupportedVMM(operation)
				}
			}
			sessions[index] = session
			seen[session] = true
		}

		// Dispatch concurrently without flooding native teardown with one
		// simultaneous close per parked vCPU.
		var joined sync.WaitGroup
		errs := make([]error, len(sessions))
		jobs := make(chan int)
		for range min(32, len(sessions)) {
			joined.Go(func() {
				for index := range jobs {
					session := sessions[index]
					if operation == "close" {
						errs[index] = session.Close()
						continue
					}
					ctx, cancel, err := session.operationContext(30)
					if err == nil {
						err = session.driver.(vmmControlDriver).Resume(ctx)
						cancel()
					}
					errs[index] = err
				}
			})
		}
		for index := range sessions {
			jobs <- index
		}
		close(jobs)
		joined.Wait()
		var first error
		failures := 0
		for index, err := range errs {
			if err != nil {
				failures++
				if first == nil {
					first = fmt.Errorf("session %d: %w", index, err)
				}
			}
		}
		if first != nil {
			return nil, normalizeVMMError(VMMErrorBackend, name, fmt.Errorf("%d of %d sessions failed: %w", failures, len(sessions), first))
		}
		return starlark.None, nil
	}
}
