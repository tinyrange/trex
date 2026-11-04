package windows

import (
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
	"testing"
)

// Package wrappers may have MUM work but no component deployment. Selection
// must use the original execution, not infer work from deployment membership.
func TestCBSSelectedExecutionActionFilter(t *testing.T) {
	names := map[string]string{}
	executions := []uup.CBSOrdinaryExecution{}
	for i := uint32(0); i <= 6; i++ {
		id := uup.AssemblyIdentity{Name: string(rune('A' + i)), Version: "1.0.0.0"}
		names[id.ExactKey()] = id.Name
		executions = append(executions, uup.CBSOrdinaryExecution{Identity: id, Action: uup.CBSExecutionAction(i), MUMPopulated: true})
	}
	fn := cbsSelectedExecutionsBuiltin(executions, names)
	packages := starlark.NewList([]starlark.Value{starlark.String("D"), starlark.String("c"), starlark.String("C"), starlark.String("B"), starlark.String("missing")})
	call := func(actions starlark.Value) (starlark.Value, error) {
		var kwargs []starlark.Tuple
		if actions != nil {
			kwargs = []starlark.Tuple{{starlark.String("actions"), actions}}
		}
		return starlark.Call(&starlark.Thread{}, fn, starlark.Tuple{packages}, kwargs)
	}
	list := func(values ...int) *starlark.List {
		out := []starlark.Value{}
		for _, v := range values {
			out = append(out, starlark.MakeInt(v))
		}
		return starlark.NewList(out)
	}
	for _, tc := range []struct {
		filter starlark.Value
		want   string
	}{
		{nil, "BCD"}, {list(3, 2, 2), "CD"}, {list(), ""}, {list(0, 6), ""},
	} {
		result, err := call(tc.filter)
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		for i := 0; i < result.(*starlark.List).Len(); i++ {
			p, _ := result.(*starlark.List).Index(i).(starlark.HasAttrs).Attr("package")
			s, _ := starlark.AsString(p)
			got += s
		}
		if got != tc.want {
			t.Fatalf("got %q want %q", got, tc.want)
		}
	}
	for _, bad := range []starlark.Value{list(-1), list(7), list(0, 0, 0, 0, 0, 0, 0, 0), starlark.NewList([]starlark.Value{starlark.String("3")}), starlark.NewList([]starlark.Value{starlark.True})} {
		if value, err := call(bad); err == nil || value != nil {
			t.Fatalf("invalid filter %v returned %v, %v", bad, value, err)
		}
	}
}
