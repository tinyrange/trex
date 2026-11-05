package windows

import (
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestCBSPreparedManifestQueries(t *testing.T) {
	globals := starlark.StringDict{
		"prepare":       starlark.NewBuiltin("prepare", cbsManifestBuiltin),
		"states":        starlark.NewBuiltin("states", cbsParentStatesBuiltin),
		"scopes":        starlark.NewBuiltin("scopes", cbsParentUpdateScopesBuiltin),
		"relationships": starlark.NewBuiltin("relationships", cbsParentRelationshipsBuiltin),
		"source":        starlark.NewBuiltin("source", cbsDeploymentSourceDataBuiltin),
		"index":         starlark.NewBuiltin("index", cbsUpdateIndexBuiltin),
	}
	_, err := starlark.ExecFile(&starlark.Thread{Name: t.Name()}, "prepared.star", `
raw=b'<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Package" version="10.0.26100.1" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"/><package><parent><assemblyIdentity name="Parent" version="10.0.26100.1" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"/></parent><update name="Exact"><component><assemblyIdentity name="Component" version="10.0.26100.1" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"/></component></update></package></assembly>'
parsed=prepare(raw)
parent='Parent~31bf3856ad364e35~amd64~~10.0.26100.1'
package='Package~31bf3856ad364e35~amd64~~10.0.26100.1'
comparison=dict(major_minor='EQ',build='EQ',revision='EQ',ignore_revision=False)
a=[dict(manifest=raw,comparisons=[comparison])]
b=[dict(manifest=parsed,comparisons=[comparison])]
def check(value):
    if not value: fail('prepared manifest differs')
check(scopes(a,[parent])==scopes(b,[parent]))
check(relationships(a,[parent])==relationships(b,[parent]))
def check_states():
    for state in [0,64,112]:
        candidates=[dict(package=parent,intended_state=state,baseline=False)]
        check(states(a,candidates)==states(b,candidates))
check_states()
check(source(raw,'Exact')==source(parsed,'Exact'))
x=index([dict(manifest=raw,intended_state=112)])
y=index([dict(manifest=parsed,intended_state=112)])
check(x.package_states()==y.package_states())
check(source(prepare(parsed),'Exact')==source(raw,'Exact'))
`, globals)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCBSPreparedManifestBounds(t *testing.T) {
	_, _, err := cbsManifestForValue(&cbsManifestValue{size: 33 << 20}, 32<<20)
	if err == nil || !strings.Contains(err.Error(), "bound") {
		t.Fatalf("prepared size bypass: %v", err)
	}
	if _, _, err := cbsManifestForValue(starlark.Bytes("<assembly>"), 32<<20); err == nil {
		t.Fatal("accepted malformed source")
	}
}

func TestAssemblyInspectionReusesPreparedManifestWithoutMutation(t *testing.T) {
	thread := &starlark.Thread{Name: t.Name()}
	_, err := starlark.ExecFile(thread, "inspection.star", `
raw = b'<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Example" version="1.0.0.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"/><file name="example.dll" hash="ABCD" hashalg="SHA256"/></assembly>'
p = prepare(raw)
a = inspect(raw)
b = inspect(p)
def check():
    if a.files[0].name != b.files[0].name or a.files[0].hash != b.files[0].hash:
        fail("prepared inspection differs")
    b.files.clear()
    b.identity.clear()
    again = inspect(p)
    if len(again.files) != 1 or len(again.identity) != 4:
        fail("inspection modified immutable parse")
check()
`, starlark.StringDict{"prepare": starlark.NewBuiltin("prepare", cbsManifestBuiltin), "inspect": starlark.NewBuiltin("inspect", assemblyManifestBuiltin)})
	if err != nil {
		t.Fatal(err)
	}
}
