package msi

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestFeatureStateOverridesPreserveUnrelatedDefaults(t *testing.T) {
	d := &Database{Tables: map[string][]map[string]starlark.Value{
		"Feature": {
			testRow("Feature", "Root", "Level", 1),
			testRow("Feature", "French", "Feature_Parent", "Root", "Level", 1, "Attributes", 26),
			testRow("Feature", "FrenchWriter", "Feature_Parent", "French", "Level", 1, "Attributes", 26),
			testRow("Feature", "FrenchHelp", "Feature_Parent", "FrenchWriter", "Level", 1, "Attributes", 26),
			testRow("Feature", "OptionalActiveX", "Feature_Parent", "Root", "Level", 200, "Attributes", 2),
		},
		"FeatureComponents":      {testRow("Feature_", "FrenchHelp", "Component_", "lang"), testRow("Feature_", "Root", "Component_", "shared")},
		"Component":              {testRow("Component", "lang"), testRow("Component", "shared")},
		"CustomAction":           {testRow("Action", "LanguageGone", "Type", 1, "Target", "Test")},
		"InstallExecuteSequence": {testRow("Action", "LanguageGone", "Condition", "&FrenchHelp=2 AND &OptionalActiveX=2", "Sequence", 1000)},
	}}
	p, err := d.Plan(PlanOptions{FeatureStates: map[string]int{"French": 2}})
	if err != nil {
		t.Fatal(err)
	}
	get := func(key string) starlark.Value { v, _, _ := p.Get(starlark.String(key)); return v }
	if got := get("selected_features").String(); got != `["Root"]` {
		t.Fatal(got)
	}
	if got := get("selected_components").String(); got != `["shared"]` {
		t.Fatal(got)
	}
	actions := get("custom_actions").(*starlark.List)
	yes, _, _ := actions.Index(0).(*starlark.Dict).Get(starlark.String("applicable_with_inputs"))
	if yes != starlark.True {
		t.Fatal(actions)
	}
	for _, states := range []map[string]int{{"missing": 2}, {"French": 4}} {
		if _, err := d.Plan(PlanOptions{FeatureStates: states}); err == nil {
			t.Fatal("invalid states accepted", states)
		}
	}
	for _, budget := range []int64{-1, (8 << 30) + 1} {
		if _, err := d.Plan(PlanOptions{CabinetCacheBytes: budget}); err == nil {
			t.Fatal("invalid cache budget accepted", budget)
		}
	}
}
