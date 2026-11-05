package windows

import (
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestCBSOrdinaryPopulationWatchBinding(t *testing.T) {
	source := `
name = "Root~31bf3856ad364e35~amd64~~10.0.26100.1"
manifest = b'<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Root" version="10.0.26100.1" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/><package><update name="f"/></package></assembly>'
index = make_index([dict(manifest=manifest,intended_state=112)])
root = dict(package=name,owner=name,state=112,integration=2,ceiling=4096)
calls = []
retained = []
def applicable(n,snapshot):
    return 112
def mum(n,snapshot,action):
    return dict(before_updates=[],deferred=[])
def initial(n,update,target,snapshot):
    calls.append("initial")
    if n != name or update != "f" or target != 112:
        fail("incorrect initial-update arguments")
    return dict(state=112,has_deployments=False)
def dependents(e,snapshot):
    calls.append("dependents")
    retained.append(e)
    if e.update_starts["f"].state != 112 or e.update_starts["f"].has_deployments:
        fail("initial update state was not retained")
    if e.dirty or e.dirty_updates != ["f"] or e.watch_processed:
        fail("incorrect initial watch dirtiness")
    return [root]
def satellites(e,n,snapshot):
    calls.append("satellites")
    if n != name or e.watch_processed or e.dirty_updates != ["f"]:
        fail("notifier cleared before satellite continuation")
    return []
result = index.ordinary_population([root],[],applicable,mum,100,watch=dict(initial_update=initial,dependents=dependents,satellites=satellites))
def check():
    if calls != ["initial","dependents","satellites"] or result.admissions != 2:
        fail("watch continuation order")
    if not result.executions[0].watch_processed or result.executions[0].dirty_updates or retained[0].dirty_updates != ["f"]:
        fail("watch result aliases notifier")
    retained[0].update_starts.clear()
    if result.executions[0].update_starts["f"].state != 112:
        fail("initial update result aliases notifier")
check()
def initial_plain(n,u,t,s):
    return dict(state=112,has_deployments=False)
def initial_bad(n,u,t,s):
    return dict(state=4096,has_deployments=False)
def empty(e,s):
    return []
def wrong(e,s):
    return {}
def sat_empty(e,n,s):
    return []
`
	thread := &starlark.Thread{Name: t.Name()}
	globals, err := starlark.ExecFile(thread, "watch.star", source, starlark.StringDict{"make_index": starlark.NewBuiltin("cbs_update_index", cbsUpdateIndexBuiltin)})
	if err != nil {
		t.Fatal(err)
	}
	fn, err := globals["index"].(starlark.HasAttrs).Attr("ordinary_population")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ initial, dependent, want string }{
		{"initial_bad", "empty", "unresolved"},
		{"initial_plain", "wrong", "request list"},
		{"", "empty", "initial_update"},
	} {
		watch := starlark.NewDict(3)
		if tc.initial != "" {
			if err := watch.SetKey(starlark.String("initial_update"), globals[tc.initial]); err != nil {
				t.Fatal(err)
			}
		}
		if err := watch.SetKey(starlark.String("dependents"), globals[tc.dependent]); err != nil {
			t.Fatal(err)
		}
		if err := watch.SetKey(starlark.String("satellites"), globals["sat_empty"]); err != nil {
			t.Fatal(err)
		}
		_, err = starlark.Call(thread, fn, starlark.Tuple{starlark.NewList([]starlark.Value{globals["root"]}), starlark.NewList(nil), globals["applicable"], globals["mum"], starlark.MakeInt(100)}, []starlark.Tuple{{starlark.String("watch"), watch}})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatal(tc, err)
		}
	}
}
