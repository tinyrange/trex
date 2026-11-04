package windows

import (
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
	"testing"
)

func TestCBSSelectedExecutionsIndependentNativeEvidence(t *testing.T) {
	a := uup.AssemblyIdentity{Name: "A", Version: "1.0.0.0"}
	b := uup.AssemblyIdentity{Name: "B", Version: "1.0.0.0"}
	executions := []uup.CBSOrdinaryExecution{{Identity: a, Action: 3, MUMPopulated: true, Updates: map[string]uint32{"f": 112}}, {Identity: b, Action: 0, Updates: map[string]uint32{"ignored": 32}}}
	names := map[string]string{a.ExactKey(): "PackageA", b.ExactKey(): "PackageB"}
	builtin := cbsSelectedExecutionsBuiltin(executions, names)
	call := func(packages ...starlark.Value) *starlark.List {
		t.Helper()
		v, err := starlark.Call(&starlark.Thread{Name: t.Name()}, builtin, starlark.Tuple{starlark.NewList(packages)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return v.(*starlark.List)
	}
	result := call(starlark.String("packagea"), starlark.String("PackageA"), starlark.String("not admitted"))
	if result.Len() != 1 {
		t.Fatal(result)
	}
	record := result.Index(0).(starlark.HasAttrs)
	packageName, _ := record.Attr("package")
	action, _ := record.Attr("action")
	if packageName.String() != `"PackageA"` || action.String() != "3" {
		t.Fatal(packageName, action)
	}
	updates, _ := record.Attr("updates")
	if err := updates.(*starlark.Dict).SetKey(starlark.String("f"), starlark.MakeInt(0)); err != nil {
		t.Fatal(err)
	}
	again := call(starlark.String("PackageA"))
	nativeUpdates, _ := again.Index(0).(starlark.HasAttrs).Attr("updates")
	value, _, _ := nativeUpdates.(*starlark.Dict).Get(starlark.String("f"))
	if value.String() != "112" || executions[0].Updates["f"] != 112 {
		t.Fatal("selection mutation changed native work")
	}
	if call().Len() != 0 {
		t.Fatal("empty selector exported all packages")
	}
	if _, err := starlark.Call(&starlark.Thread{}, builtin, starlark.Tuple{starlark.NewList([]starlark.Value{starlark.MakeInt(1)})}, nil); err == nil {
		t.Fatal("accepted a non-string selector")
	}
}
