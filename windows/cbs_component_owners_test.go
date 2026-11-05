package windows

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestCBSComponentOwnersBuiltin(t *testing.T) {
	globals := starlark.StringDict{"owners": starlark.NewBuiltin("owners", cbsComponentOwnersBuiltin)}
	script := `
def check(b):
    if not b: fail("component owner reduction mismatch")
a=dict(source="Package.Update",elevation=128)
b=dict(source="Package.Update",elevation=8)
rtm=dict(source=None,elevation=2)
install=dict(source=a["source"],elevation=128,action="install")
remove=dict(source=a["source"],elevation=128,action="uninstall")
r=owners([rtm,a,b],[a],[remove])
check(r.installed==[rtm,b])
check(r.pinned==[a])
check(owners([],[],[install,remove,install]).installed==[])
check(owners(r.installed,r.pinned,[remove]).installed==[b])
check(a["elevation"]==128)
`
	state, err := starlark.ExecFile(&starlark.Thread{Name: "component owners"}, "owners.star", script, globals)
	if err != nil {
		t.Fatal(err)
	}
	state["owners"] = globals["owners"]
	for _, bad := range []string{
		`owners([],[],[dict(source=None,elevation=128,action="install")])`,
		`owners([],[],[dict(source="x",elevation=True,action="install")])`,
		`owners([],[],[dict(source="x",elevation=-1,action="install")])`,
		`owners([],[],[dict(source="x",elevation=4294967296,action="install")])`,
		`owners([],[],[dict(source="x",elevation=128,action="stage")])`,
		`owners([],[],[dict(source="x",elevation=128,action="uninstall")])`,
		`owners([dict(source=b"x",elevation=128)],[],[])`,
		`owners([dict(source="x",elevation=128,unknown=True)],[],[])`,
	} {
		if _, err := starlark.Eval(&starlark.Thread{Name: "invalid owners"}, "bad.star", bad, state); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
