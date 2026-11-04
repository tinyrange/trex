package windows

import (
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

func TestCSISourcePlanBuiltin(t *testing.T) {
	globals := starlark.StringDict{
		"encode": starlark.NewBuiltin("cbs_deployment_source_data", cbsDeploymentSourceDataBuiltin),
		"decode": starlark.NewBuiltin("cbs_deployment_source", cbsDeploymentSourceBuiltin),
		"plan":   starlark.NewBuiltin("csi_source_plan", csiSourcePlanBuiltin),
	}
	state, err := starlark.ExecFile(&starlark.Thread{Name: t.Name()}, "sources.star", `
mum='<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Package" version="10.0.1.1" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"/><package><update name="Exact"><component><assemblyIdentity name="A"/></component><applicable><updateComponent elevate="build"><assemblyIdentity name="A"/></updateComponent></applicable></update></package></assembly>'
data=encode(mum,"Exact")
name="p!"+decode(data).source_key
baseline=[dict(name=name,type=3,data=data)]
result=plan(baseline,[dict(kind=1,delete=False,data=data),dict(kind=4,delete=False,data=data)])
def check():
    if len(result.edits)!=1 or result.edits[0].name!="s!"+name[2:] or result.edits[0].data!=data or result.edits[0].type!=3 or result.edits[0].delete:
        fail("wrong source edits")
    if result.before.pinned!=1 or result.before.staged!=0 or result.after.pinned!=1 or result.after.staged!=1 or result.after.installed!=0:
        fail("lost source kind counts")
check()
`, globals)
	if err != nil {
		t.Fatal(err)
	}
	state["plan"] = globals["plan"]
	for _, tc := range []struct{ expr, message string }{
		{`plan(baseline,[dict(kind=4,delete=False,data=str(data))])`, "bytes"},
		{`plan([dict(name=name,type=3,data=str(data))],[])`, "bytes"},
		{`plan(baseline,[dict(kind=-1,delete=False,data=data)])`, "unsigned 32-bit"},
		{`plan(baseline,[dict(kind=3,delete=False,data=data)])`, "mask"},
		{`plan(baseline,[dict(kind=2,delete=True,data=data)])`, "absent"},
		{`plan(baseline,[dict(kind=2,data=data)])`, "delete"},
		{`plan(baseline,[1])`, "dict"},
		{`plan([1],[])`, "dict"},
	} {
		_, err := starlark.Eval(&starlark.Thread{Name: t.Name()}, "invalid.star", tc.expr, state)
		if err == nil || !strings.Contains(err.Error(), tc.message) {
			t.Fatal(tc.expr, err)
		}
	}
}
