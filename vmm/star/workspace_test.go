package star

import (
	"context"
	"image"
	"testing"

	"github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

type workspaceDisplayValue struct{}

func (*workspaceDisplayValue) String() string                           { return "<display>" }
func (*workspaceDisplayValue) Type() string                             { return "display" }
func (*workspaceDisplayValue) Freeze()                                  {}
func (*workspaceDisplayValue) Truth() starlark.Bool                     { return true }
func (*workspaceDisplayValue) Hash() (uint32, error)                    { return 0, nil }
func (d *workspaceDisplayValue) VMMDisplay() (vmm.DisplaySource, error) { return d, nil }
func (*workspaceDisplayValue) Capture(context.Context) (*image.RGBA, error) {
	return image.NewRGBA(image.Rect(0, 0, 2, 2)), nil
}
func (*workspaceDisplayValue) Input(context.Context, vmm.Input) error { return nil }

func TestScriptedWorkspaceRegistrationNeverReusesIDs(t *testing.T) {
	thread := &starlark.Thread{}
	value, err := workspaceBuiltin(thread, nil, starlark.Tuple{starlark.NewDict(0)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := value.(*workspaceValue)
	if len(w.VMs()) != 0 {
		t.Fatal("empty workspace started a VM")
	}
	add, _ := w.Attr("add")
	remove, _ := w.Attr("remove")
	register := func(name string) string {
		t.Helper()
		id, err := starlark.Call(thread, add.(starlark.Callable), starlark.Tuple{starlark.String(name), &workspaceDisplayValue{}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		result, _ := starlark.AsString(id)
		return result
	}
	first, second := register("First"), register("Second")
	if _, err := starlark.Call(thread, remove.(starlark.Callable), starlark.Tuple{starlark.String(first)}, nil); err != nil {
		t.Fatal(err)
	}
	if retained := w.sessions[:cap(w.sessions)][len(w.sessions)]; retained != nil {
		t.Fatal("removed session retained in workspace backing array")
	}
	replacement := register("First")
	if replacement == first || replacement == second {
		t.Fatal("stale browser connection could select replacement VM")
	}
	if _, err := starlark.Call(thread, add.(starlark.Callable), starlark.Tuple{starlark.String("First"), &workspaceDisplayValue{}}, nil); err == nil {
		t.Fatal("duplicate VM name accepted")
	}
	if len(w.VMs()) != 2 || len(w.sessions) != 2 {
		t.Fatal("registration/session ownership diverged")
	}
}
