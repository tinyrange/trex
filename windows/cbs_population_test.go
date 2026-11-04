package windows

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"

	"go.starlark.net/starlark"
)

func TestCBSOrdinaryPopulationBinding(t *testing.T) {
	source := `
name = "Root~31bf3856ad364e35~amd64~~10.0.26100.1"
manifest = b'<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Root" version="10.0.26100.1" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/><package><update name="f"/></package></assembly>'
old = make_index([dict(manifest=manifest,intended_state=0)])
root = dict(package=name,owner=name,state=112,integration=3,ceiling=4096)
snapshots = []
def applicable(package, snapshot):
    snapshots.append(snapshot)
    return 112
def mum(package, snapshot, action):
    if action != 3:
        fail("wrong MUM action")
    if snapshot.package_states()[name] != 112:
        fail("MUM did not see admission")
    return dict(before_updates=[],deferred=[])
result = old.ordinary_population([root],[],applicable,mum,100)
e = result.executions[0]
def check():
    if result.admissions != 1 or e.package != name or e.intended_state != 112 or not e.mum_populated or not e.mum_processed or e.mum_passes != 1 or e.action != 3 or not e.dirty:
        fail("bad execution")
    if e.owners[0].integration != 3 or e.owners[0].state != 112 or e.updates["f"] != 112:
        fail("bad owner/publication")
    states = result.index.package_states()
    states[name] = 0
    if result.index.package_states()[name] != 112 or old.package_states()[name] != 0 or snapshots[0].package_states()[name] != 0:
        fail("snapshot alias")
check()
def applicable_plain(package,snapshot):
    return 112
def bad_applicable(package,snapshot):
    return 4096
def bad_mum(package,snapshot,action):
    return dict(before_updates=[])
def failed_mum(package,snapshot,action):
    fail("intentional policy failure")
`
	thread := &starlark.Thread{Name: t.Name()}
	globals, err := starlark.ExecFile(thread, "population.star", source, starlark.StringDict{"make_index": starlark.NewBuiltin("cbs_update_index", cbsUpdateIndexBuiltin)})
	if err != nil {
		t.Fatal(err)
	}
	old := globals["old"].(starlark.HasAttrs)
	population, err := old.Attr("ordinary_population")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		app, mum string
		contains string
	}{
		{"bad_applicable", "mum", "unresolved"},
		{"applicable_plain", "bad_mum", "deferred"},
		{"applicable_plain", "failed_mum", "intentional policy failure"},
	} {
		_, err := starlark.Call(thread, population, starlark.Tuple{starlark.NewList([]starlark.Value{globals["root"]}), starlark.NewList(nil), globals[tc.app], globals[tc.mum], starlark.MakeInt(100)}, nil)
		if err == nil || !strings.Contains(err.Error(), tc.contains) {
			t.Fatal(tc, err)
		}
	}
	for _, bad := range []starlark.Value{starlark.True, starlark.MakeInt(-1), starlark.MakeUint64(1 << 32)} {
		request := starlark.NewDict(5)
		for _, item := range globals["root"].(*starlark.Dict).Items() {
			if err := request.SetKey(item[0], item[1]); err != nil {
				t.Fatal(err)
			}
		}
		if err := request.SetKey(starlark.String("state"), bad); err != nil {
			t.Fatal(err)
		}
		_, err := starlark.Call(thread, population, starlark.Tuple{starlark.NewList([]starlark.Value{request}), starlark.NewList(nil), globals["applicable"], globals["mum"], starlark.MakeInt(100)}, nil)
		if err == nil {
			t.Fatal("invalid DWORD accepted", bad)
		}
	}
}

func TestCBSPopulationLazyExecutions(t *testing.T) {
	for _, freezeFirst := range []bool{false, true} {
		t.Run(fmt.Sprint("freezeFirst=", freezeFirst), func(t *testing.T) {
			id := uup.AssemblyIdentity{Name: "Root", Version: "10.0.26100.1"}
			native := []uup.CBSOrdinaryExecution{{Identity: id, Updates: map[string]uint32{"f": 112}}}
			r := &cbsPopulationRecord{
				Record:           starvalue.NewRecord(starlark.StringDict{"execution_count": starlark.MakeInt(1)}),
				nativeExecutions: native, names: map[string]string{id.ExactKey(): "Root"},
			}
			count, err := r.Attr("execution_count")
			if err != nil || count.String() != "1" || r.executions != nil {
				t.Fatal("count materialized executions", count, err)
			}
			if !slices.Contains(r.AttrNames(), "executions") || !strings.Contains(r.String(), "executions") || r.executions != nil {
				t.Fatal("inspection should advertise executions without materializing them")
			}
			if freezeFirst {
				r.Freeze()
				if r.executions != nil {
					t.Fatal("Freeze materialized executions")
				}
			}
			value, err := r.Attr("executions")
			if err != nil {
				t.Fatal(err)
			}
			list := value.(*starlark.List)
			entry := list.Index(0).(starlark.HasAttrs)
			updatesValue, err := entry.Attr("updates")
			if err != nil {
				t.Fatal(err)
			}
			updates := updatesValue.(*starlark.Dict)
			if !freezeFirst {
				if err := updates.SetKey(starlark.String("f"), starlark.MakeInt(0)); err != nil {
					t.Fatal(err)
				}
				if native[0].Updates["f"] != 112 {
					t.Fatal("inspection mutation changed native evidence")
				}
				// A mutable inspection list may form a cycle back to its owner.
				if err := list.Append(r); err != nil {
					t.Fatal(err)
				}
				again, err := r.Attr("executions")
				if err != nil || again != list || list.Len() != 2 {
					t.Fatal("lost list identity", err)
				}
				r.Freeze()
			}
			if err := list.Append(starlark.None); err == nil {
				t.Fatal("frozen list is mutable")
			}
			if err := updates.SetKey(starlark.String("f"), starlark.MakeInt(0)); err == nil {
				t.Fatal("nested frozen dictionary is mutable")
			}
		})
	}
}

func TestCBSPopulationFrozenConcurrentExecutions(t *testing.T) {
	r := &cbsPopulationRecord{Record: starvalue.NewRecord(nil), nativeExecutions: []uup.CBSOrdinaryExecution{{}}}
	r.Freeze()
	values := make([]starlark.Value, 8)
	var wg sync.WaitGroup
	for i := range values {
		wg.Go(func() {
			var err error
			values[i], err = r.Attr("executions")
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	for _, value := range values {
		if value == nil || value != values[0] {
			t.Fatal("concurrent readers got different lists")
		}
	}
	if err := values[0].(*starlark.List).Clear(); err == nil {
		t.Fatal("deferred list was not frozen")
	}
}
