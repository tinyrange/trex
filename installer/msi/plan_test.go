package msi

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func testRow(values ...any) map[string]starlark.Value {
	row := map[string]starlark.Value{}
	for i := 0; i < len(values); i += 2 {
		var v starlark.Value
		switch x := values[i+1].(type) {
		case string:
			v = starlark.String(x)
		case int:
			v = starlark.MakeInt(x)
		case nil:
			v = starlark.None
		}
		row[values[i].(string)] = v
	}
	return row
}
func TestFreshFileAndRegistryPlan(t *testing.T) {
	d := &Database{Tables: map[string][]map[string]starlark.Value{
		"Directory":         {testRow("Directory", "TARGETDIR", "Directory_Parent", nil, "DefaultDir", "SourceDir"), testRow("Directory", "APP", "Directory_Parent", "TARGETDIR", "DefaultDir", "App:media")},
		"Feature":           {testRow("Feature", "Core", "Level", 1), testRow("Feature", "Optional", "Level", 2)},
		"FeatureComponents": {testRow("Feature_", "Core", "Component_", "core"), testRow("Feature_", "Optional", "Component_", "optional")},
		"Component":         {testRow("Component", "core", "Directory_", "APP", "Condition", "NOT Installed"), testRow("Component", "optional", "Directory_", "APP")},
		"File":              {testRow("File", "data", "Component_", "core", "FileName", "DATA.TXT|data.txt", "FileSize", 5, "Sequence", 1, "Attributes", 8192, "Version", nil, "Language", nil), testRow("File", "optional", "Component_", "optional", "FileName", "optional", "FileSize", 9)},
		"Registry":          {testRow("Registry", "value", "Component_", "core", "Root", 2, "Key", `Software\Example`, "Name", "Binary", "Value", "#x00ff")},
	}}
	p, err := d.Plan(PlanOptions{Properties: map[string]string{"ROOTDRIVE": `C:\`}, Media: map[string]starfile.File{"media/data.txt": &starfile.Bytes{Data: []byte("hello")}}})
	if err != nil {
		t.Fatal(err)
	}
	get := func(key string) starlark.Value { v, _, _ := p.Get(starlark.String(key)); return v }
	if get("unresolved").(*starlark.List).Len() != 0 {
		t.Fatal(get("unresolved"))
	}
	files := get("files").(*starlark.List)
	if files.Len() != 1 {
		t.Fatal(files)
	}
	dest, _, _ := files.Index(0).(*starlark.Dict).Get(starlark.String("destination"))
	if dest != starlark.String(`C:\App\data.txt`) {
		t.Fatal(dest)
	}
	reg := get("definitive_registry_writes").(*starlark.List)
	data, _, _ := reg.Index(0).(*starlark.Dict).Get(starlark.String("data"))
	if data != starlark.Bytes("\x00\xff") {
		t.Fatal(data)
	}
}

func TestDirectoryNamePairs(t *testing.T) {
	for _, tc := range []struct {
		value, target, source string
		short                 bool
	}{
		{"SHORT|Long:SOURCE|Source Long", "Long", "Source Long", false},
		{"SHORT|Long:SOURCE|Source Long", "Long", "SOURCE", true},
		{".:common|.:common", ".", "common", false},
		{"Help|Help", "Help", "Help", false},
	} {
		target, source := directoryNames(tc.value, tc.short)
		if target != tc.target || source != tc.source {
			t.Errorf("%q: %q, %q", tc.value, target, source)
		}
	}
}

func TestStaticPlanRetainsConditionalCustomActionsAndQueries(t *testing.T) {
	d := &Database{Tables: map[string][]map[string]starlark.Value{
		"AppSearch":              {testRow("Property", "SDKROOT", "Signature_", "InstalledSDK")},
		"RegLocator":             {testRow("Signature_", "InstalledSDK", "Root", 2, "Key", `Software\SDK`)},
		"CustomAction":           {testRow("Action", "Configure", "Type", 1, "Source", "Helper", "Target", "ConfigureSDK")},
		"InstallExecuteSequence": {testRow("Action", "Configure", "Sequence", 4000, "Condition", "SDKROOT")},
	}}
	p, err := d.Plan(PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	get := func(key string) starlark.Value { v, _, _ := p.Get(starlark.String(key)); return v }
	if get("unresolved").(*starlark.List).Len() != 0 {
		t.Fatal(p)
	}
	if get("custom_actions").(*starlark.List).Len() != 1 {
		t.Fatal("query-dependent action was dropped", p)
	}
	if get("runtime_dependencies").(*starlark.List).Len() != 4 {
		t.Fatal(p)
	}
	if get("database") != d {
		t.Fatal("source declarations unavailable")
	}
	if _, found, _ := p.Get(starlark.String("modifications")); found {
		t.Fatal("static plan exposes incomplete executable modifications")
	}
}

func TestRegistryMultiStringMergePolicies(t *testing.T) {
	for _, tc := range []struct{ input, merge string }{{"[~]new", "append"}, {"new[~]", "prepend"}, {"[~]new[~]", "replace"}} {
		d := &Database{Tables: map[string][]map[string]starlark.Value{
			"Feature":           {testRow("Feature", "Core", "Level", 1)},
			"FeatureComponents": {testRow("Feature_", "Core", "Component_", "core")},
			"Component":         {testRow("Component", "core")},
			"Registry":          {testRow("Registry", "multi", "Component_", "core", "Root", 2, "Key", "K", "Name", "V", "Value", tc.input)},
		}}
		p, err := d.Plan(PlanOptions{})
		if err != nil {
			t.Fatal(err)
		}
		v, _, _ := p.Get(starlark.String("definitive_registry_writes"))
		row := v.(*starlark.List).Index(0).(*starlark.Dict)
		merge, _, _ := row.Get(starlark.String("merge"))
		if merge != starlark.String(tc.merge) {
			t.Fatal(tc, row)
		}
	}
}
