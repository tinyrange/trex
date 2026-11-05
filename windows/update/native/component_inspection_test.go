package native

import (
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
	"testing"
)

func TestComponentInspectionPaginationAndProvenance(t *testing.T) {
	makeComponent := func(name, version string) uup.PlannedComponent {
		return uup.PlannedComponent{
			Path: `image1\` + name + ".manifest", Identity: uup.AssemblyIdentity{Name: name, Version: version},
			Stem: name + version, PreviousStem: name + "old", SelectedBy: "package owner",
		}
	}
	plans := []uup.StageAssemblyPlan{{Components: []uup.PlannedComponent{makeComponent("Alpha", "1"), makeComponent("Beta", "1")}}, {Components: []uup.PlannedComponent{makeComponent("Alpha", "2")}}}
	features := []string{"first", "second"}
	for _, tc := range []struct {
		feature, prefix                   string
		offset, limit, total, count, next int
		more                              bool
		version                           string
	}{
		{"", "AL", 0, 1, 2, 1, 1, true, "1"},
		{"", "al", 1, 1, 2, 1, 2, false, "2"},
		{"SECOND", "a", 0, 10, 1, 1, 1, false, "2"},
		{"", "", 0, 0, 3, 0, 0, true, ""},
		{"", "", 100, 1, 3, 0, 3, false, ""},
	} {
		v, err := inspectServicingComponents(plans, features, tc.feature, tc.prefix, tc.offset, tc.limit)
		if err != nil {
			t.Fatal(err)
		}
		r := v.(starlark.HasAttrs)
		for name, want := range map[string]int{"total": tc.total, "next_offset": tc.next} {
			got, _ := r.Attr(name)
			n, err := starlark.AsInt32(got)
			if err != nil || n != want {
				t.Fatalf("%+v %s=%s want %d", tc, name, got, want)
			}
		}
		more, _ := r.Attr("has_more")
		if more.Truth() != starlark.Bool(tc.more) {
			t.Fatal(tc, more)
		}
		items, _ := r.Attr("components")
		list := items.(*starlark.List)
		if list.Len() != tc.count {
			t.Fatal(tc, list)
		}
		if list.Len() > 0 {
			item := list.Index(0).(starlark.HasAttrs)
			for name, want := range map[string]string{"version": tc.version, "previous_stem": "Alphaold", "store_path": "/Windows/WinSxS/Manifests/Alpha.manifest", "selected_by": "package owner"} {
				got, _ := item.Attr(name)
				if got != starlark.String(want) {
					t.Fatalf("%s=%s want %s", name, got, want)
				}
			}
		}
	}
	for _, bounds := range [][2]int{{-1, 1}, {0, -1}, {0, 1001}} {
		if _, err := inspectServicingComponents(plans, features, "", "", bounds[0], bounds[1]); err == nil {
			t.Fatal("accepted bounds", bounds)
		}
	}
	if _, err := inspectServicingComponents(plans, nil, "", "", 0, 1); err == nil {
		t.Fatal("accepted mismatched metadata")
	}
	if _, err := inspectServicingComponents(plans, features, "unknown", "", 0, 1); err == nil {
		t.Fatal("accepted unknown feature")
	}
}
