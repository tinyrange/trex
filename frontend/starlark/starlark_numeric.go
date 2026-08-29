package starlarkfrontend

import (
	"fmt"
	"math"

	"go.starlark.net/starlark"
)

// starlarkNumber accepts both Starlark int and float values. Starlark APIs use
// it for durations because callers naturally spell whole seconds as 30 while
// still needing fractional deadlines for protocol work.
type starlarkNumber float64

func (n *starlarkNumber) Unpack(value starlark.Value) error {
	number, ok := starlark.AsFloat(value)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) {
		return fmt.Errorf("got %s, want finite int or float", value.Type())
	}
	*n = starlarkNumber(number)
	return nil
}
