package msi

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestFormattedDirectorySeparators(t *testing.T) {
	d := &Database{Tables: map[string][]map[string]starlark.Value{
		"Directory": {
			testRow("Directory", "TARGETDIR", "Directory_Parent", nil, "DefaultDir", "SourceDir"),
			testRow("Directory", "APP", "Directory_Parent", "TARGETDIR", "DefaultDir", "App"),
			testRow("Directory", "CHILD", "Directory_Parent", "APP", "DefaultDir", "Child"),
		},
		"Feature":           {testRow("Feature", "Core", "Level", 1)},
		"FeatureComponents": {testRow("Feature_", "Core", "Component_", "core")},
		"Component":         {testRow("Component", "core", "Directory_", "CHILD")},
		"File":              {testRow("File", "data", "Component_", "core", "FileName", "data.dll", "FileSize", 1, "Sequence", 1)},
	}}
	p, err := d.Plan(PlanOptions{Properties: map[string]string{
		"ROOTDRIVE": `C:\`, "APP": `C:\Program Files (x86)\\Application Verifier//`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	dirs, _, _ := p.Get(starlark.String("directory_paths"))
	child, _, _ := dirs.(*starlark.Dict).Get(starlark.String("CHILD"))
	if child != starlark.String(`C:\Program Files (x86)\Application Verifier\Child\`) {
		t.Fatal(child)
	}
	files, _, _ := p.Get(starlark.String("files"))
	dest, _, _ := files.(*starlark.List).Index(0).(*starlark.Dict).Get(starlark.String("destination"))
	if dest != starlark.String(`C:\Program Files (x86)\Application Verifier\Child\data.dll`) {
		t.Fatal(dest)
	}
	for _, value := range []string{`[UNKNOWN]\\App`, `\\server\share\`, `C:\App\..\Outside`} {
		if got := canonicalDirectory(value); got != value {
			t.Fatalf("changed non-separator semantics: %q => %q", value, got)
		}
	}
}
