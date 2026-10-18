package windows

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestStateRepositoryDictionaryReadBuiltin(t *testing.T) {
	env := starlark.StringDict{
		"encode": Builtins()["state_repository_dictionary"],
		"decode": Builtins()["state_repository_dictionary_read"],
	}
	for _, expr := range []string{
		`decode(encode({"visible": True, "name": "é", "properties": {"#text": "1"}, "children": [{"x": False}]})) == {"visible": True, "name": "é", "properties": {"#text": "1"}, "children": [{"x": False}]}`,
		`decode(b"SRD1\x0c\x00\x00\x00\x00\x00\x00\x00") == {}`,
	} {
		result, err := starlark.Eval(&starlark.Thread{Name: "read"}, "test.star", expr, env)
		if err != nil || result != starlark.True {
			t.Fatalf("%s: %v, %v", expr, result, err)
		}
	}
	for _, expr := range []string{
		`decode(b"SRD1")`,
		`decode(b"SRD1\x0c\x00\x00\x00\x01\x00\x00\x00")`,
		`decode(b"SRD1\x0c\x00\x00\x00\x00\x00\x00\x00extra")`,
		`decode(123)`,
	} {
		if _, err := starlark.Eval(&starlark.Thread{Name: "bad"}, "test.star", expr, env); err == nil {
			t.Fatalf("accepted %s", expr)
		}
	}
}
