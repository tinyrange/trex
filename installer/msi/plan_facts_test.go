package msi

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestDirectoryPropertyConcatenationAndSelectionFacts(t *testing.T) {
	d := &Database{Tables: map[string][]map[string]starlark.Value{
		"Directory":         {testRow("Directory", "TARGETDIR", "DefaultDir", "SourceDir"), testRow("Directory", "APP", "Directory_Parent", "TARGETDIR", "DefaultDir", "App")},
		"Feature":           {testRow("Feature", "Core", "Level", 1), testRow("Feature", "Optional", "Level", 2)},
		"FeatureComponents": {testRow("Feature_", "Core", "Component_", "core"), testRow("Feature_", "Optional", "Component_", "optional")},
		"Component":         {testRow("Component", "core", "Directory_", "APP"), testRow("Component", "optional", "Directory_", "APP")},
		"Registry":          {testRow("Registry", "path", "Component_", "core", "Root", 2, "Key", `Software\Example`, "Name", "Command", "Value", `[APP]tool.exe`)},
		"Property":          {testRow("Property", "OLDROOT", "Value", "stale")},
		"AppSearch":         {testRow("Property", "OLDROOT", "Signature_", "OldInstallation")},
	}}
	p, err := d.Plan(PlanOptions{Properties: map[string]string{"ROOTDRIVE": `C:\`}})
	if err != nil {
		t.Fatal(err)
	}
	get := func(key string) starlark.Value { v, _, _ := p.Get(starlark.String(key)); return v }
	if got := get("selected_components").String(); got != `["core"]` {
		t.Fatal(got)
	}
	known := get("resolved_properties").(*starlark.Dict)
	if _, found, _ := known.Get(starlark.String("OLDROOT")); found {
		t.Fatal("unknown search leaked stale default")
	}
	dirs := get("directory_paths").(*starlark.Dict)
	app, _, _ := dirs.Get(starlark.String("APP"))
	if app != starlark.String(`C:\App\`) {
		t.Fatal(app)
	}
	reg := get("definitive_registry_writes").(*starlark.List).Index(0).(*starlark.Dict)
	value, _, _ := reg.Get(starlark.String("data"))
	if value != starlark.String(`C:\App\tool.exe`) {
		t.Fatal(value)
	}
}

func TestPropertyClearBeforeCosting(t *testing.T) {
	d := &Database{Tables: map[string][]map[string]starlark.Value{
		"Property":               {testRow("Property", "ADD_PATH", "Value", "0")},
		"CustomAction":           {testRow("Action", "DeleteIfOff", "Type", 307, "Source", "ADD_PATH", "Target", "{}")},
		"InstallExecuteSequence": {testRow("Action", "DeleteIfOff", "Sequence", 500, "Condition", `ADD_PATH="0"`), testRow("Action", "CostFinalize", "Sequence", 1000)},
		"Feature":                {testRow("Feature", "Main", "Level", 1)},
		"FeatureComponents":      {testRow("Feature_", "Main", "Component_", "path")},
		"Component":              {testRow("Component", "path", "Condition", "ADD_PATH")},
	}}
	p, err := d.Plan(PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	selected, _, _ := p.Get(starlark.String("selected_components"))
	if selected.(*starlark.List).Len() != 0 {
		t.Fatal("cleared property selected a component", p)
	}
}

func TestEarlyPropertyActionsExecuteOnlyOnce(t *testing.T) {
	d := &Database{Tables: map[string][]map[string]starlark.Value{
		"CustomAction":           {testRow("Action", "Default", "Type", 307, "Source", "OPT", "Target", "1"), testRow("Action", "Clear", "Type", 307, "Source", "OPT", "Target", "{}"), testRow("Action", "Off", "Type", 51, "Source", "OPT", "Target", "0"), testRow("Action", "Enroll", "Type", 3137, "Source", "CA", "Target", "Enroll")},
		"InstallExecuteSequence": {testRow("Action", "Default", "Sequence", 500, "Condition", "NOT OPT"), testRow("Action", "Clear", "Sequence", 501, "Condition", "OPT<>1"), testRow("Action", "CostFinalize", "Sequence", 1000), testRow("Action", "Off", "Sequence", 1100, "Condition", "NOT OPT"), testRow("Action", "Enroll", "Sequence", 4000, "Condition", "OPT=1")},
	}}
	p, err := d.Plan(PlanOptions{Properties: map[string]string{"OPT": "0"}})
	if err != nil {
		t.Fatal(err)
	}
	props, _, _ := p.Get(starlark.String("resolved_properties"))
	value, _, _ := props.(*starlark.Dict).Get(starlark.String("OPT"))
	if value != starlark.String("0") {
		t.Fatalf("opt-out was overwritten: %s", value)
	}
	actions, _, _ := p.Get(starlark.String("custom_actions"))
	expected := []starlark.Value{starlark.False, starlark.True, starlark.True, starlark.False}
	for i, want := range expected {
		got, _, _ := actions.(*starlark.List).Index(i).(*starlark.Dict).Get(starlark.String("applicable_with_inputs"))
		if got != want {
			t.Fatalf("action %d applicability %s want %s", i, got, want)
		}
	}
}
