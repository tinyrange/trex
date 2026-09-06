package starlarkfrontend

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestRenvoExamplesExecute(t *testing.T) {
	for _, test := range []struct{ name, want string }{{"renvo_cc", "C returned 42\n"}, {"renvo_make", "Make returned 42\n"}} {
		t.Run(test.name, func(t *testing.T) {
			thread, env, err := newStarlarkRuntime("-")
			if err != nil {
				t.Fatal(err)
			}
			var output string
			env["stdout"] = starlark.NewBuiltin("stdout", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
				output += string(args[0].(starlark.Bytes))
				return starlark.None, nil
			})
			globals, err := thread.Load(thread, "//scripts/examples:"+test.name+".star")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := starlark.Call(thread, globals["main"], starlark.Tuple{starlark.Tuple{}}, nil); err != nil {
				t.Fatal(err)
			}
			if output != test.want {
				t.Fatalf("output = %q, want %q", output, test.want)
			}
		})
	}
}
