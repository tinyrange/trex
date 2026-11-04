package windows

import (
	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
	"testing"
)

func TestCDFFileMapTransitionBuiltin(t *testing.T) {
	source := `owner = [("", "Name", "Component"), ("", "Version", "10.0.26100.1")]
doc = dict(path="System32", root_selector=1, identities=[], entries=[])
node = dict(name="example.dll", operation=1, state=2, directory_flags=0, file_flags=1, before_identity=None, after_identity=owner)
transition = cdf_filemap_transition(doc, [node])
result = transition["document"]
if transition["directory_collisions"]:
    fail("unexpected collision")
if doc["entries"] or doc["identities"]:
    fail("input mutated")
roundtrip = cdf_filemap(cdf_filemap_encode(result))
if roundtrip != result:
    fail("transition result lost at language boundary")
node["operation"] = 2
node["state"] = 0
node["after_identity"] = None
empty = cdf_filemap_transition(result, [node])["document"]
if empty["entries"] or empty["identities"]:
    fail("removed entry retained")
`
	globals, err := starlark.ExecFileOptions(&syntax.FileOptions{TopLevelControl: true}, &starlark.Thread{Name: "cdf-transition"}, "cdf.star", source, Builtins())
	if err != nil {
		t.Fatal(err)
	}
	node := starlark.NewDict(8)
	for _, item := range globals["node"].(*starlark.Dict).Items() {
		if err := node.SetKey(item[0], item[1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []starlark.Value{starlark.MakeInt(-1), starlark.MakeInt(256), starlark.String("2"), starlark.True} {
		if err := node.SetKey(starlark.String("state"), bad); err != nil {
			t.Fatal(err)
		}
		if _, err := starlark.Call(&starlark.Thread{}, Builtins()["cdf_filemap_transition"], starlark.Tuple{globals["result"], starlark.NewList([]starlark.Value{node})}, nil); err == nil {
			t.Fatalf("invalid state accepted: %s", bad)
		}
	}
	if _, err := starlark.Call(&starlark.Thread{}, Builtins()["cdf_filemap_encode"], starlark.Tuple{globals["empty"]}, nil); err == nil {
		t.Fatal("empty transition silently serialized")
	}
}
