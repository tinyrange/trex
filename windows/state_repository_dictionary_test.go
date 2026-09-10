package windows

import (
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/srdictionary"
	"go.starlark.net/starlark"
)

func TestStateRepositoryDictionaryBuiltin(t *testing.T) {
	value, err := starlark.Eval(&starlark.Thread{Name: "dictionary"}, "test.star",
		`encode({"LaunchPolicy": {"#text": "1"}, "Capability": [{"Name": "a"}, {"Name": "b"}]})`,
		starlark.StringDict{"encode": Builtins()["state_repository_dictionary"]})
	if err != nil {
		t.Fatal(err)
	}
	d, err := srdictionary.Decode(value.(*starfile.Bytes).Data)
	if err != nil {
		t.Fatal(err)
	}
	if d[0].Key != "LaunchPolicy" || d[0].Value.(srdictionary.Dictionary)[0].Value != "1" || len(d[1].Value.([]srdictionary.Dictionary)) != 2 {
		t.Fatalf("wrong dictionary: %#v", d)
	}
	for _, expr := range []string{`encode({"x": 1})`, `encode({1: "x"})`, `encode({"x": ["not a map"]})`} {
		if _, err := starlark.Eval(&starlark.Thread{Name: "bad"}, "bad.star", expr, starlark.StringDict{"encode": Builtins()["state_repository_dictionary"]}); err == nil {
			t.Fatalf("accepted %s", expr)
		}
	}
	cycle := starlark.NewDict(1)
	if err := cycle.SetKey(starlark.String("self"), cycle); err != nil {
		t.Fatal(err)
	}
	if _, err := stateRepositoryDictionary(cycle, 0); err == nil {
		t.Fatal("accepted dictionary cycle")
	}
}
