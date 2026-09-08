// Package exports implements architecture-independent semantic export batches.
package exports

import (
	"fmt"
	"go.starlark.net/starlark"
)

// Provide preserves dictionary order and delegates each binding to the same
// implementation used for an individual export. Symbol/arity validation happens
// before publication; loader errors retain ordinary sequential-call semantics.
func Provide(args starlark.Tuple, kwargs []starlark.Tuple, bind func(starlark.Tuple, []starlark.Tuple) (starlark.Value, error)) (starlark.Value, error) {
	var callback starlark.Callable
	var module string
	var signatures *starlark.Dict
	convention := "stdcall"
	if err := starlark.UnpackArgs("provide_exports", args, kwargs, "callback", &callback, "module", &module, "signatures", &signatures, "convention?", &convention); err != nil {
		return nil, err
	}
	if module == "" || (convention != "stdcall" && convention != "cdecl" && convention != "win64") {
		return nil, fmt.Errorf("provide_exports: invalid module or convention")
	}
	items := signatures.Items()
	for _, item := range items {
		name, ok := starlark.AsString(item[0])
		var argc int
		if !ok || name == "" || starlark.AsInt(item[1], &argc) != nil || argc < 0 || argc > 4096 {
			return nil, fmt.Errorf("provide_exports: signatures must map nonempty names to argument counts in 0..4096")
		}
	}
	parameters := []starlark.Tuple{
		{starlark.String("module"), starlark.String(module)},
		{starlark.String("name"), starlark.None},
		{starlark.String("argc"), starlark.None},
		{starlark.String("convention"), starlark.String(convention)},
	}
	callArgs := starlark.Tuple{callback}
	out := make([]starlark.Value, 0, len(items))
	for _, item := range items {
		parameters[1][1], parameters[2][1] = item[0], item[1]
		value, err := bind(callArgs, parameters)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return starlark.NewList(out), nil
}
