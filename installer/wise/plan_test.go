package wise

import (
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

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
