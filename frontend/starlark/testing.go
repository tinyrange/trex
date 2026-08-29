package starlarkfrontend

import (
	"fmt"

	"go.starlark.net/starlark"
)

// testingNamespace exposes error capture and module introspection to the
// portable Starlark test runner. Test selection, assertions, and reporting stay
// in Starlark so the same suites run from go test and the trex CLI.
func testingNamespace() namespace {
	return namespace{
		name: "testing",
		attrs: starlark.StringDict{
			"attempt": starlark.NewBuiltin("attempt", testingAttemptBuiltin),
			"module":  starlark.NewBuiltin("module", testingModuleBuiltin),
		},
	}
}

func testingModuleBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var label string
	if err := starlark.UnpackArgs("module", args, kwargs, "label", &label); err != nil {
		return nil, err
	}
	if thread.Load == nil {
		return nil, fmt.Errorf("module: runtime has no module loader")
	}
	globals, err := thread.Load(thread, label)
	if err != nil {
		return nil, err
	}
	result := starlark.NewDict(len(globals))
	for name, value := range globals {
		if err := result.SetKey(starlark.String(name), value); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func testingAttemptBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var callback starlark.Callable
	arguments := starlark.Value(starlark.None)
	keywordArguments := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("attempt", args, kwargs, "callback", &callback, "args?", &arguments, "kwargs?", &keywordArguments); err != nil {
		return nil, err
	}

	callArgs := starlark.Tuple{}
	if arguments != starlark.None {
		iterable, ok := arguments.(starlark.Iterable)
		if !ok {
			return nil, fmt.Errorf("attempt: args must be iterable")
		}
		iterator := iterable.Iterate()
		defer iterator.Done()
		var value starlark.Value
		for iterator.Next(&value) {
			callArgs = append(callArgs, value)
		}
	}

	callKwargs := []starlark.Tuple{}
	if keywordArguments != starlark.None {
		dictionary, ok := keywordArguments.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("attempt: kwargs must be a dict")
		}
		for _, item := range dictionary.Items() {
			name, ok := starlark.AsString(item[0])
			if !ok {
				return nil, fmt.Errorf("attempt: keyword name must be a string")
			}
			callKwargs = append(callKwargs, starlark.Tuple{starlark.String(name), item[1]})
		}
	}

	value, err := starlark.Call(thread, callback, callArgs, callKwargs)
	fields := map[string]starlark.Value{
		"ok":    starlark.Bool(err == nil),
		"value": value,
		"error": starlark.String(""),
	}
	if err != nil {
		fields["value"] = starlark.None
		fields["error"] = starlark.String(err.Error())
	}
	return newStarlarkRecord(fields), nil
}
