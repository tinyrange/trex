package windows

import (
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestCSIWinnerChangeBuiltin(t *testing.T) {
	globals := starlark.StringDict{"winner": starlark.NewBuiltin("csi_winner_change", csiWinnerChangeBuiltin)}
	state, err := starlark.ExecFile(&starlark.Thread{Name: t.Name()}, "winner.star", `
id=b"Family, Culture=neutral, Version=10.0.1.1, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=NonSxS"
old="10.0.1.1"
new="10.0.1.2"
no=winner(id,old,[old,new],[dict(version=new,installed=True,impactful_install=False)])
yes=winner(id,old,[old,new],[dict(version=new,installed=True,impactful_install=True)])
removed=winner(id,old,[],[dict(version=old,installed=False,impactful_install=True)])
def check():
    if (no.winner,no.shadowed)!=("","") or (yes.winner,yes.shadowed)!=(new,old) or (removed.winner,removed.shadowed)!=("",old):
        fail("winner binding lost independent impact or removal")
check()
`, globals)
	if err != nil {
		t.Fatal(err)
	}
	state["winner"] = globals["winner"]
	for _, tc := range []struct{ expr, message string }{
		{`winner(id,old,[],[])`, "absent"},
		{`winner(id,old,[old],[dict(version=new,installed=True,impactful_install=True)])`, "membership"},
		{`winner(id,old,[old],[dict(version=old,installed=True)])`, "impactful_install"},
		{`winner(id,old,[1],[])`, "string"},
		{`winner(id,old,[old],[1])`, "dict"},
	} {
		_, err := starlark.Eval(&starlark.Thread{Name: t.Name()}, "bad.star", tc.expr, state)
		if err == nil || !strings.Contains(err.Error(), tc.message) {
			t.Fatal(tc.expr, err)
		}
	}
}
