package native

import (
	"testing"

	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func TestComponentStagingRejectsActivationAndInvalidInputs(t *testing.T) {
	stage := &uup.CumulativeStage{}
	for _, plan := range []uup.StageEffectPlan{
		{RegistryKeys: []uup.StageRegistryKeyEffect{{KeyName: "runtime"}}},
		{RegistryValues: []uup.StageRegistryEffect{{}}},
		{Files: []uup.StageFileEffect{{Destinations: []string{"runtime"}}}},
	} {
		if v, err := componentStagingRecord(stage, plan, nil); err == nil || v != nil {
			t.Fatal("accepted runtime activation", v, err)
		}
	}
	thread := &starlark.Thread{Name: "component staging test"}
	builtin := exactComponentPlanBuiltin(stage, nil)
	for _, input := range []starlark.Value{
		starlark.String("identity"),
		starlark.NewList([]starlark.Value{starlark.String("identity")}),
		starlark.NewList([]starlark.Value{starlark.Bytes("invalid")}),
	} {
		if v, err := starlark.Call(thread, builtin, starlark.Tuple{input}, nil); err == nil || v != nil {
			t.Fatal("accepted invalid identity request", v, err)
		}
	}
	v, err := componentStagingRecord(stage, uup.StageEffectPlan{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := v.(starlark.HasAttrs)
	files, _ := r.Attr("files")
	if err := files.(*starlark.List).Append(starlark.None); err == nil {
		t.Fatal("mutable published staging inventory")
	}
	open, _ := r.Attr("open")
	for _, n := range []int{-1, 0, 1} {
		if v, err := starlark.Call(thread, open, starlark.Tuple{starlark.MakeInt(n)}, nil); err == nil || v != nil {
			t.Fatal("accepted invalid file index", v, err)
		}
	}
}
