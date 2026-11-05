package windows

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestCBSComponentSnapshotBuiltin(t *testing.T) {
	globals := starlark.StringDict{"index": starlark.NewBuiltin("index", cbsUpdateIndexBuiltin)}
	script := `
def check(b):
    if not b: fail("component snapshot mismatch")
manifest=b'<assembly><assemblyIdentity name="Package" version="10.0.26100.1" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/><package><update name="a"><applicable disposition="staged"><updateComponent elevate="build"><assemblyIdentity name="NetFx" version="4.0.15920.116" processorArchitecture="x86" publicKeyToken="b03f5f7f11d50a3a" language="neutral"/></updateComponent></applicable></update></package></assembly>'
name="Package~31bf3856ad364e35~amd64~~10.0.26100.1"
i=index([dict(manifest=manifest,intended_state=112)])
entries=[dict(identity=b'NetFx, Culture=neutral, Version=4.0.15912.0, PublicKeyToken=b03f5f7f11d50a3a, ProcessorArchitecture=x86',owners=[128])]
active=i.with_components(entries)
check(active.state(name,"a").raw_state==112)
entries[0]["owners"][0]=8
inactive=i.with_components(entries)
check(inactive.state(name,"a").raw_state==64)
check(active.state(name,"a").raw_state==112)
check(active.with_components([]).state(name,"a").raw_state==64)
`
	state, err := starlark.ExecFile(&starlark.Thread{Name: "component snapshot"}, "components.star", script, globals)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`i.state(name,"a")`,
		`i.with_components([dict(identity="string",owners=[128])])`,
		`i.with_components([dict(identity=entries[0]["identity"],owners=[True])])`,
		`i.with_components([dict(identity=entries[0]["identity"],owners=[-1])])`,
		`i.with_components([dict(identity=entries[0]["identity"],owners=[16])])`,
		`i.with_components(entries+entries)`,
	} {
		if _, err := starlark.Eval(&starlark.Thread{Name: "invalid components"}, "invalid.star", bad, state); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
