package windows

import (
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

func TestCSICompositionBuiltin(t *testing.T) {
	globals := starlark.StringDict{"composition": starlark.NewBuiltin("composition", csiCompositionBuiltin), "parsed": starlark.NewBuiltin("parsed", cbsManifestBuiltin)}
	script := `
root=b"Root, Culture=neutral, Version=10.0.26100.1, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64"
child=b"Child, Culture=neutral, Version=10.0.26100.1, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64"
def identity(name):
    return '<assemblyIdentity name="'+name+'" version="10.0.26100.1" language="neutral" publicKeyToken="31bf3856ad364e35" processorArchitecture="amd64"/>'
def resolve(i):
    if i == root:
        return '<assembly>'+identity('Root')+'<dependency><dependentAssembly dependencyType="install">'+identity('Child')+'</dependentAssembly></dependency></assembly>'
    if i == child:
        return '<assembly>'+identity('Child')+'<deployment impact="patch"/></assembly>'
    fail("unexpected lookup")
r=composition(root,resolve)
def check(r):
    if len(r)!=2 or r[0].identity!=root or r[0].disposition!=2 or r[1].identity!=child or r[1].disposition!=1:
        fail("composition callback mismatch")
check(r)
parsed_values={root:parsed(resolve(root)), child:parsed(resolve(child))}
def resolve_parsed(i):
    return parsed_values[i]
check(composition(root,resolve_parsed))
# Reusing the parse must still check identity and traversal bounds.
def wrong_identity(i):
    return parsed_values[child]
def missing(i):
    return None
def broken(i):
    fail("resolver-marker")
`
	state, err := starlark.ExecFile(&starlark.Thread{Name: "composition"}, "composition.star", script, globals)
	if err != nil {
		t.Fatal(err)
	}
	state["composition"] = globals["composition"]
	for _, tc := range []struct{ expression, contains string }{
		{`composition(root,missing)`, "missing exact component"},
		{`composition(root,wrong_identity)`, "identity"},
		{`composition(root,resolve_parsed,work_limit=1)`, "work limit"},
		{`composition(root,broken)`, "resolver-marker"},
		{`composition(root,resolve,work_limit=1)`, "work limit"},
		{`composition(root,resolve,work_limit=-1)`, "work limit"},
		{`composition("not bytes",resolve)`, "bytes"},
	} {
		_, err := starlark.Eval(&starlark.Thread{Name: "bad composition"}, "bad.star", tc.expression, state)
		if err == nil || !strings.Contains(err.Error(), tc.contains) {
			t.Fatalf("%s: %v", tc.expression, err)
		}
	}
}
