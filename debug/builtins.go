package debug

import (
	"fmt"
	"io"
	"reflect"
	"time"

	starvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
)

type debugSelectable interface {
	DebugReady() <-chan struct{}
}

func Builtins() starlark.StringDict {
	return starlark.StringDict{
		"disassemble": starlark.NewBuiltin("disassemble", DisassembleBuiltin),
		"gdb":         starlark.NewBuiltin("gdb", GDBBuiltin),
		"select":      starlark.NewBuiltin("select", SelectBuiltin),
	}
}

func SelectBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var values *starlark.List
	timeout := starvalue.Number(-1)
	if err := starlark.UnpackArgs("select", args, kwargs, "values", &values, "timeout?", &timeout); err != nil {
		return nil, err
	}
	if values == nil || values.Len() == 0 {
		return nil, fmt.Errorf("select: values must not be empty")
	}
	if timeout < -1 || timeout > 86400 {
		return nil, fmt.Errorf("select: invalid timeout")
	}
	cases := make([]reflect.SelectCase, 0, values.Len()+1)
	indexes := make([]int, 0, values.Len())
	for index := 0; index < values.Len(); index++ {
		selectable, ok := values.Index(index).(debugSelectable)
		if !ok {
			return nil, fmt.Errorf("select: values[%d] of type %s is not selectable", index, values.Index(index).Type())
		}
		ready := selectable.DebugReady()
		if ready == nil {
			return nil, fmt.Errorf("select: values[%d] of type %s does not expose event readiness", index, values.Index(index).Type())
		}
		cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ready)})
		indexes = append(indexes, index)
	}
	var timer *time.Timer
	var timeoutChannel <-chan time.Time
	if timeout >= 0 {
		timer = time.NewTimer(time.Duration(float64(timeout) * float64(time.Second)))
		timeoutChannel = timer.C
		defer timer.Stop()
	}
	cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(timeoutChannel)})
	chosen, _, open := reflect.Select(cases)
	if chosen == len(cases)-1 {
		return starlark.None, nil
	}
	if !open {
		return nil, io.EOF
	}
	return values.Index(indexes[chosen]), nil
}
