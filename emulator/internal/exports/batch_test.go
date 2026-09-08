package exports

import (
	"fmt"
	"testing"

	"go.starlark.net/starlark"
)

func TestBatchValidationBeforePublication(t *testing.T) {
	callback := starlark.NewBuiltin("callback", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		return starlark.None, nil
	})
	for _, invalid := range []starlark.Tuple{
		{starlark.String(""), starlark.MakeInt(1)},
		{starlark.MakeInt(1), starlark.MakeInt(1)},
		{starlark.String("Bad"), starlark.MakeInt(-1)},
		{starlark.String("Bad"), starlark.MakeInt(4097)},
		{starlark.String("Bad"), starlark.String("2")},
	} {
		signatures := starlark.NewDict(2)
		_ = signatures.SetKey(starlark.String("Good"), starlark.MakeInt(0))
		_ = signatures.SetKey(invalid[0], invalid[1])
		calls := 0
		_, err := Provide(starlark.Tuple{callback, starlark.String("test.dll"), signatures}, nil, func(starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
			calls++
			return starlark.None, nil
		})
		if err == nil || calls != 0 {
			t.Fatalf("invalid %v: err=%v, published=%d", invalid, err, calls)
		}
	}
}

func TestBatchStopsAtBindingFailure(t *testing.T) {
	callback := starlark.NewBuiltin("callback", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		return starlark.None, nil
	})
	signatures := starlark.NewDict(3)
	for _, name := range []string{"first", "second", "third"} {
		_ = signatures.SetKey(starlark.String(name), starlark.MakeInt(2))
	}
	calls := 0
	_, err := Provide(starlark.Tuple{callback, starlark.String("test.dll"), signatures}, nil, func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		calls++
		if args[0] != callback || kwargs[2][1] != starlark.MakeInt(2) {
			t.Fatal("binding changed callback or arity")
		}
		if calls == 2 {
			return nil, fmt.Errorf("binding failed")
		}
		return starlark.MakeInt(calls), nil
	})
	if err == nil || calls != 2 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}
