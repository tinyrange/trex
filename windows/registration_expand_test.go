package windows

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestRegistrationExpandMatchesStarlark(t *testing.T) {
	thread := &starlark.Thread{Name: "expansion"}
	globals, err := starlark.ExecFile(thread, "reference.star", `
def reference(value, replacements):
    if type(value) != "string":
        return value
    output = value
    for _ in range(4):
        previous = output
        for name, replacement in replacements.items():
            output = output.replace("%" + name.upper() + "%", replacement)
            output = output.replace("%" + name.lower() + "%", replacement)
        if output == previous:
            break
    return output
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, expression := range []string{
		`("%FOO%/%foo%/%Foo%/%missing%", {"foo": "bar"})`,
		`("%A%", {"A": "%B%", "B": "done"})`,
		`("%A%", {"B": "done", "A": "%B%"})`,
		`("%A%", {"A": "%A%x"})`,
		`("%A%", {"A": "%B%", "B": "%A%"})`,
		`("%Ä%/%ä%", {"ä": "unicode"})`,
		`("%%", {"": "empty"})`,
		`("plain", {})`,
		`(None, {"foo": 7})`,
		`(7, {})`,
	} {
		t.Run(expression, func(t *testing.T) {
			args, err := starlark.Eval(thread, "args.star", expression, nil)
			if err != nil {
				t.Fatal(err)
			}
			want, err := starlark.Call(thread, globals["reference"], args.(starlark.Tuple), nil)
			if err != nil {
				t.Fatal(err)
			}
			got, err := registrationExpandBuiltin(thread, nil, args.(starlark.Tuple), nil)
			if err != nil {
				t.Fatal(err)
			}
			equal, err := starlark.Equal(got, want)
			if err != nil || !equal {
				t.Fatalf("got %s, want %s: %v", got, want, err)
			}
		})
	}
}
