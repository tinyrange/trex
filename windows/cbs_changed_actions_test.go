package windows

import (
	"errors"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
	"testing"
)

func TestCBSChangedActionsPreserveStageAndOrderAfterValidation(t *testing.T) {
	id := uup.AssemblyIdentity{Name: "P", Version: "1.0.0.0"}
	actions := []uup.CBSDeploymentAction{
		{Package: id, UpdateName: "unchanged"},
		{Package: id, UpdateName: "stage-only", Stage: true},
		{Package: id, UpdateName: "install", Action: uup.CBSActionInstall},
		{Package: id, UpdateName: "unchanged-after"},
		{Package: id, UpdateName: "uninstall", Action: uup.CBSActionUninstall},
	}
	calls := 0
	var failure error
	fn := cbsDeploymentActionsFromProvider(func() ([]uup.CBSDeploymentAction, error) { calls++; return actions, failure }, map[string]string{id.ExactKey(): "P"})
	kwargs := []starlark.Tuple{{starlark.String("changed_only"), starlark.True}}
	v, err := starlark.Call(&starlark.Thread{}, fn, nil, kwargs)
	if err != nil {
		t.Fatal(err)
	}
	list := v.(*starlark.List)
	if list.Len() != 3 || calls != 1 {
		t.Fatal(list, calls)
	}
	for i, want := range []string{"stage-only", "install", "uninstall"} {
		update, _ := list.Index(i).(starlark.HasAttrs).Attr("update")
		if update != starlark.String(want) {
			t.Fatal("lost order or stage-only action", i, update)
		}
	}
	if err := list.Clear(); err != nil {
		t.Fatal(err)
	}
	full, err := starlark.Call(&starlark.Thread{}, fn, nil, nil)
	if err != nil || full.(*starlark.List).Len() != 5 {
		t.Fatal("default inventory changed", full, err)
	}
	failure = errors.New("invalid unchanged metadata")
	if partial, err := starlark.Call(&starlark.Thread{}, fn, nil, kwargs); partial != nil || !errors.Is(err, failure) {
		t.Fatal("selection hid invalid full inventory", partial, err)
	}
}
