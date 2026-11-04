package windows

import (
	"testing"

	"go.starlark.net/starlark"
)

func TestCBSParentStatesBuiltin(t *testing.T) {
	thread := &starlark.Thread{Name: "CBS parent query"}
	_, err := starlark.ExecFile(thread, "cbs_parent_query.star", `
def check(condition):
    if not condition:
        fail("parent state mismatch")
name = "Feature~31bf3856ad364e35~amd64~~10.0.26100.1742"
manifest = b'<assembly><assemblyIdentity name="wrapper"/><package><parent integrate="separate"><assemblyIdentity name="Feature" publicKeyToken="31bf3856ad364e35" processorArchitecture="amd64" language="neutral" version="10.0.26100.1742"/></parent></package></assembly>'
comparison = dict(major_minor="EQ", build="EQ", revision="GE", ignore_revision=False)
packages = [dict(manifest=manifest, comparisons=[comparison])]
candidates = [dict(package=name, intended_state=64, baseline=True), dict(package=name.replace("1742", "1"), intended_state=112, baseline=False)]
check(query(packages, candidates) == [112])
candidates[0]["baseline"] = False
check(query(packages, candidates) == [64])
comparison["ignore_revision"] = True
check(query(packages, candidates) == [112])
comparison["revision"] = "EQ"
check(query(packages, candidates) == [64])
`, starlark.StringDict{"query": starlark.NewBuiltin("query", cbsParentStatesBuiltin)})
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{
		`query([], [dict(package="Feature~31bf3856ad364e35~amd64~~10.0.26100.1", intended_state=112)])`,
		`query([], [dict(package="Feature~31bf3856ad364e35~amd64~~10.0.26100.1", intended_state=112, baseline="false")])`,
		`query([], [dict(package="Feature~31bf3856ad364e35~amd64~~10.0.26100.1", intended_state=4294967408, baseline=False)])`,
		`query([dict(manifest=b'<assembly><assemblyIdentity name="wrapper"/><package><parent><assemblyIdentity name="Feature"/></parent></package></assembly>', comparisons=[])], [])`,
	} {
		if _, err := starlark.ExecFile(thread, "invalid_cbs_parent.star", script, starlark.StringDict{"query": starlark.NewBuiltin("query", cbsParentStatesBuiltin)}); err == nil {
			t.Fatalf("accepted %s", script)
		}
	}
}

func TestCBSParentUpdateScopesBuiltin(t *testing.T) {
	thread := &starlark.Thread{Name: "CBS parent scope query"}
	globals := starlark.StringDict{"query": starlark.NewBuiltin("query", cbsParentUpdateScopesBuiltin), "relationships": starlark.NewBuiltin("relationships", cbsParentRelationshipsBuiltin)}
	_, err := starlark.ExecFile(thread, "cbs_parent_scope.star", `
def check(condition):
    if not condition:
        fail("parent scope mismatch")
name = "Feature~31bf3856ad364e35~amd64~~10.0.26100.1742"
manifest = b'<assembly><assemblyIdentity name="wrapper"/><package><parent><assemblyIdentity name="Feature" publicKeyToken="31bf3856ad364e35" processorArchitecture="amd64" language="neutral" version="10.0.26100.1742"/></parent></package></assembly>'
comparison = dict(major_minor="EQ", build="EQ", revision="GE", ignore_revision=False)
packages = [dict(manifest=manifest, comparisons=[comparison])]
candidates = [name.replace("1742", "1"), name, name.replace("1742", "9457")]
check(query(packages, candidates) == [[name, candidates[2]]])
comparison["ignore_revision"] = True
check(query(packages, candidates) == [candidates])
comparison["revision"] = "EQ"
check(query(packages, candidates) == [[name]])
check(relationships(packages, candidates) == [candidates])
comparison["ignore_revision"] = False
check(relationships(packages, candidates) == [[name]])
check(relationships(packages, []) == [[]])
check(query(packages, []) == [[]])
`, globals)
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{
		`query([], [dict(package="Feature~31bf3856ad364e35~amd64~~10.0.26100.1")])`,
		`query([], ["Feature~31bf3856ad364e35~amd64~~10.0.26100.1", "feature~31bf3856ad364e35~amd64~~10.0.26100.1"])`,
		`query([dict(manifest=b'<assembly><assemblyIdentity name="wrapper"/><package/></assembly>', comparisons=[], standalone_satisfied=True)], [])`,
		`query([dict(manifest=b'<assembly><assemblyIdentity name="wrapper"/><package/></assembly>', comparisons=[]), dict(manifest=b'<assembly><assemblyIdentity name="wrapper"/><package><parent/></package></assembly>', comparisons=[])], [])`,
	} {
		if result, err := starlark.ExecFile(thread, "invalid_scope.star", script, globals); err == nil || result["result"] != nil {
			t.Fatalf("accepted malformed query %s: %v", script, err)
		}
	}
}
