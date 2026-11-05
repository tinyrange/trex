package windows

import (
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestCBSDeploymentActionsBindingSnapshot(t *testing.T) {
	source := `
name = "Root~31bf3856ad364e35~amd64~~10.0.26100.1"
manifest = b'<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Root" version="10.0.26100.1" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/><package><update name="Payload"><driver><assemblyIdentity name="Driver" version="10.0.26100.2" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" type="win32"/></driver></update></package></assembly>'
index = make_index([dict(manifest=manifest,intended_state=112)])
root = dict(package=name,owner=name,state=112,integration=2,ceiling=4096)
def applicable(n,s):
    return 112
def mum(n,s,a):
    return dict(before_updates=[],deferred=[])
def initial(n,u,t,s):
    return dict(state=0,has_deployments=True)
def dep(e,s):
    return []
def sat(e,n,s):
    return []
result = index.ordinary_population([root,root],[],applicable,mum,100,watch=dict(initial_update=initial,dependents=dep,satellites=sat))
# Inspection records are mutable, but they do not grant mutation of the native
# snapshot retained by the bound method.
result.executions[0].update_starts.clear()
result.executions[0].updates.clear()
result.executions.clear()
actions = result.deployment_actions()
def check():
    if len(actions) != 1:
        fail("lost deployment after mutating inspection records")
    a = actions[0]
    if a.package != name or a.update != "Payload" or not a.driver or not a.stage or a.action != 3:
        fail("incorrect execution projection")
    if a.deployment.name != "Driver" or a.deployment.version != "10.0.26100.2" or a.deployment.version_scope != "nonSxS" or a.deployment.type != "win32":
        fail("lost exact deployment identity")
    actions.clear()
    if len(result.deployment_actions()) != 1:
        fail("result aliases a prior projection")
check()
identity = b"Driver, Culture=neutral, Type=win32, Version=10.0.26100.2, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS"
def resolve(identity):
    return b'<assembly><assemblyIdentity name="Driver" version="10.0.26100.2" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" type="win32"/></assembly>'
inventory = [dict(identity=identity, composition=composition(identity,resolve), installed_sources=[])]
marks = result.install_marks(inventory)
def check_marks():
    if len(marks)!=1 or marks[0].identity!=identity or marks[0].initial!=0 or marks[0].final!=1 or not marks[0].affected or not marks[0].impactful_install:
        fail("install marks lost native population or exact driver identity")
check_marks()
partial = index.ordinary_population([root],[],applicable,mum,100)
`

	for _, compact := range []bool{false, true} {
		script := source
		method := "deployment_actions"
		if compact {
			script = strings.Replace(script, "result = index.ordinary_population", "original = index.ordinary_population", 1)
			script = strings.Replace(script, "# Inspection records", "result = original.deployment_plan()\noriginal.executions.clear()\n# Inspection records", 1)
			method = "deployment_plan"
		}
		thread := &starlark.Thread{Name: t.Name()}
		globals, err := starlark.ExecFile(thread, "actions.star", script, starlark.StringDict{"make_index": starlark.NewBuiltin("cbs_update_index", cbsUpdateIndexBuiltin), "composition": starlark.NewBuiltin("csi_composition", csiCompositionBuiltin)})
		if err != nil {
			t.Fatal(compact, err)
		}
		if compact {
			result := globals["result"].(starlark.HasAttrs)
			if index, err := result.Attr("index"); err != nil || index != nil {
				t.Fatal("compact projection retained index", index, err)
			}
			selected, _ := result.Attr("selected_executions")
			v, err := starlark.Call(thread, selected, starlark.Tuple{starlark.NewList([]starlark.Value{globals["name"]})}, nil)
			if err != nil || v.(*starlark.List).Len() != 1 {
				t.Fatal("lost native executions", err)
			}
		}
		fn, err := globals["partial"].(starlark.HasAttrs).Attr(method)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = starlark.Call(thread, fn, nil, nil); err == nil || !strings.Contains(err.Error(), "initial/target") {
			t.Fatal(compact, err)
		}
	}
}
