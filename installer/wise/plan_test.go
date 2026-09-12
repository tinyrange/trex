package wise

import (
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestPlanReportsUnmodeledLocalCopies(t *testing.T) {
	for _, source := range []string{`%TEMP%\program.exe`, `%PREVIOUS_FILE%`, ""} {
		archive := &Archive{script: &wiseScript{
			file: &starfile.Bytes{Name: "WiseScript.bin"},
			actions: []scriptAction{{offset: 0x123, opcode: 0x12,
				strings: []string{`%MAINDIR%\program.exe`, "", "", source}}},
		}}
		plan, err := archive.Plan(map[string]string{"<TARGETDIR>": `C:\Program Files\Example`}, nil)
		if err != nil {
			t.Fatal(err)
		}
		gaps := planValue(t, plan, "unresolved").(*starlark.List)
		if source == "" {
			if gaps.Len() != 0 {
				t.Fatal("empty source cannot produce a copy")
			}
		} else if gaps.Len() != 1 || !strings.Contains(gaps.Index(0).String(), "copy_local_file at 0x123") {
			t.Fatalf("missing copy provenance: %s", gaps)
		}
	}
}

func TestCopySourceIsEvaluatedBeforeLaterAssignments(t *testing.T) {
	script := &wiseScript{actions: []scriptAction{
		{opcode: 0x12, strings: []string{`%MAINDIR%\program.exe`, "", "", "%SOURCE%"}},
		{opcode: 0x09, strings: []string{"", "f16", "", "", "0\x7fSOURCE\x7f"}},
	}}
	evaluation := evaluateWiseScript(script, map[string]string{"SOURCE": `C:\TEMP\program.exe`})
	if evaluation.variables["SOURCE"] != "" || evaluation.states[0]["SOURCE"] != `C:\TEMP\program.exe` {
		t.Fatal("later assignment erased the reached copy source")
	}
}

func TestPlanDerivesPortableModifications(t *testing.T) {
	program := &starfile.Bytes{Name: "program.exe", Data: []byte("not a PE")}
	file := &scriptFile{destination: `%MAINDIR%\program.exe`, member: "/payload/0001/program.exe"}
	script := &wiseScript{
		file:  &starfile.Bytes{Name: "WiseScript.bin", Data: []byte("script")},
		files: []*scriptFile{file},
		actions: []scriptAction{
			{opcode: 0x09, strings: []string{"", "f16", "", "", "0\x7fMAINDIR\x7f%PROGRAM_FILES%\\Demo"}},
			{opcode: 0x00, file: file},
			{opcode: 0x0a, fixed: []byte{2, 0}, strings: []string{`Software\Demo`, `%MAINDIR%\program.exe %%1`, "Command"}},
			{opcode: 0x09, strings: []string{"", "ShellLink", "", "", "0\x7f%MAINDIR%\\program.exe\x7f%GROUPDIR%\\Demo.lnk\x7f\x7f%MAINDIR%\x7f0\x7f\x7f"}},
		},
	}
	archive := &Archive{
		script:  script,
		members: []member{{name: file.member, file: program}},
		index:   map[string]int{file.member: 0},
	}
	plan, err := archive.Plan(map[string]string{
		"<PROGRAMFILES>":        `C:\Program Files`,
		"<WINSYSDIR>":           `C:\WINDOWS\SYSTEM`,
		"<SHELL_OBJECT_FOLDER>": `C:\WINDOWS\Start Menu\Programs`,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	files := planValue(t, plan, "files").(*starlark.List)
	if files.Len() != 1 {
		t.Fatalf("files = %d, want 1", files.Len())
	}
	entry := files.Index(0).(*starlark.Dict)
	if got := dictString(t, entry, "destination"); got != `C:\Program Files\Demo\program.exe` {
		t.Fatalf("destination = %q", got)
	}
	writes := planValue(t, plan, "definitive_registry_writes").(*starlark.List)
	if writes.Len() != 1 {
		t.Fatalf("registry writes = %d, want 1", writes.Len())
	}
	write := writes.Index(0).(*starlark.Dict)
	if got := dictString(t, write, "data"); got != `C:\Program Files\Demo\program.exe %1` {
		t.Fatalf("registry data = %q", got)
	}
	shortcuts := planValue(t, plan, "shortcuts").(*starlark.List)
	if shortcuts.Len() != 1 {
		t.Fatalf("shortcuts = %d, want 1", shortcuts.Len())
	}
}

func TestEvaluateWiseScriptSelectsDefaultBranches(t *testing.T) {
	script := &wiseScript{actions: []scriptAction{
		{opcode: 0x09, fixed: []byte{9}, strings: []string{"", "f16", "", "", "128\x7fOPTION\x7fA"}},
		{opcode: 0x0c, fixed: []byte{2}, strings: []string{"OPTION", "A"}},
		{opcode: 0x0a, fixed: []byte{1, 0}, strings: []string{"Selected", "yes", ""}},
		{opcode: 0x0d},
		{opcode: 0x0a, fixed: []byte{1, 0}, strings: []string{"Selected", "no", ""}},
		{opcode: 0x08, fixed: []byte{0}},
		{opcode: 0x0c, fixed: []byte{10}, strings: []string{"REGCODE", "0123456789"}},
		{opcode: 0x0a, fixed: []byte{1, 0}, strings: []string{"Registered", "yes", ""}},
		{opcode: 0x0d},
		{opcode: 0x0a, fixed: []byte{1, 0}, strings: []string{"Registered", "no", ""}},
		{opcode: 0x08, fixed: []byte{0}},
	}}
	evaluation := evaluateWiseScript(script, map[string]string{})
	for _, index := range []int{0, 2, 9} {
		if !evaluation.active[index] || evaluation.uncertain[index] {
			t.Fatalf("action %d was not definitively selected", index)
		}
	}
	for _, index := range []int{4, 7} {
		if evaluation.active[index] || evaluation.uncertain[index] {
			t.Fatalf("action %d was not definitively rejected", index)
		}
	}
}

func planValue(t *testing.T, plan *starlark.Dict, name string) starlark.Value {
	t.Helper()
	value, found, err := plan.Get(starlark.String(name))
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("plan has no %q", name)
	}
	return value
}

func dictString(t *testing.T, dict *starlark.Dict, name string) string {
	t.Helper()
	value, found, err := dict.Get(starlark.String(name))
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("dict has no %q", name)
	}
	output, ok := starlark.AsString(value)
	if !ok {
		t.Fatalf("%q is %s, want string", name, value.Type())
	}
	return output
}

func TestPlanLocalCopiesKeepActionTimeDestinations(t *testing.T) {
	program := &starfile.Bytes{Name: "program.exe", Data: []byte("program")}
	set := func(name, value string) scriptAction {
		return scriptAction{opcode: 9, strings: []string{"", "f16", "", "", "0\x7f" + name + "\x7f" + value}}
	}
	archive := &Archive{script: &wiseScript{file: program, actions: []scriptAction{
		set("MAINDIR", `C:\Suite\First`),
		{opcode: 0x12, strings: []string{`%MAINDIR%\program.exe`, "", "", `%TEMP%\program.exe`}},
		{opcode: 0x0a, fixed: []byte{2, 0}, strings: []string{`Software\First`, `%MAINDIR%\program.exe`, "Path"}},
		set("MAINDIR", `C:\Suite\Second`),
		{opcode: 0x12, strings: []string{`%MAINDIR%\program.exe`, "", "", `C:\Suite\First\program.exe`}},
	}}}
	plan, err := archive.PlanWithLocalFiles(nil, nil, map[string]starfile.File{`c:/windows/temp/PROGRAM.EXE`: program})
	if err != nil {
		t.Fatal(err)
	}
	if gaps := planValue(t, plan, "unresolved").(*starlark.List); gaps.Len() != 0 {
		t.Fatal(gaps)
	}
	files := planValue(t, plan, "files").(*starlark.List)
	if files.Len() != 2 {
		t.Fatal(files)
	}
	for index, want := range []string{`C:\Suite\First\program.exe`, `C:\Suite\Second\program.exe`} {
		entry := files.Index(index).(*starlark.Dict)
		if got := dictString(t, entry, "destination"); got != want {
			t.Fatalf("destination=%q want %q", got, want)
		}
		if planValue(t, entry, "file") != program {
			t.Fatal("copy lost its in-memory source")
		}
	}
	writes := planValue(t, plan, "definitive_registry_writes").(*starlark.List)
	if got := dictString(t, writes.Index(0).(*starlark.Dict), "data"); got != `C:\Suite\First\program.exe` {
		t.Fatal(got)
	}
}

func TestWisePathAndSubstringOperations(t *testing.T) {
	variables := map[string]string{"MAINDIR": `C:\Suite\CuteFTP`, "COMPONENTS": "AG"}
	wiseApplyVariableAction(scriptAction{strings: []string{"", "f27", "", "", "0\x7f%MAINDIR%\x7fCuteFTP\x7fHTML_DIR\x7fTRASH"}}, variables)
	wiseApplyVariableAction(scriptAction{strings: []string{"", "f16", "", "", "12\x7fHTML_DIR\x7f%HTML_DIR%"}}, variables)
	if variables["HTML_DIR"] != `C:\Suite` {
		t.Fatal(variables)
	}
	if yes, known := wiseCondition(scriptAction{fixed: []byte{2}, strings: []string{"COMPONENTS", "G"}}, variables); !yes || !known {
		t.Fatal("component substring was not selected")
	}
	if yes, known := wiseCondition(scriptAction{fixed: []byte{3}, strings: []string{"HTML_DIR", `\`}}, variables); yes || !known {
		t.Fatal("path delimiter was not found")
	}
}
