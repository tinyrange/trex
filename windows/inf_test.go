package windows

import (
	"testing"

	"go.starlark.net/starlark"
)

func TestExpandINFStringPreservesEscapedPercent(t *testing.T) {
	got := expandINFString(`%%SystemRoot%%\System32\%Module%`, map[string]string{
		"MODULE": "example.dll",
	})
	if want := `%SystemRoot%\System32\example.dll`; got != want {
		t.Fatalf("expandINFString() = %q, want %q", got, want)
	}
}

func TestParseINFExpandsStringTokensInKeys(t *testing.T) {
	inf, err := parseINF(`
[Models]
%Example.DeviceDesc%=ExampleInstall,PCI\VEN_1234&DEV_5678
[Strings]
example.devicedesc=Example Network Adapter
`)
	if err != nil {
		t.Fatal(err)
	}
	models, ok, err := infSection(inf, "Models")
	if err != nil || !ok {
		t.Fatalf("Models section: found=%t err=%v", ok, err)
	}
	value, ok, err := models.Get(starlark.String("Example Network Adapter"))
	if err != nil || !ok {
		t.Fatalf("expanded model key: found=%t err=%v", ok, err)
	}
	row, ok := value.(*starlark.List)
	if !ok || row.Len() != 2 || firstInfString(row.Index(0)) != "ExampleInstall" {
		t.Fatalf("expanded model row = %v", value)
	}
}

func TestSplitINFCSVPreservesDoubledQuotes(t *testing.T) {
	got := splitINFCSV(`"",0x00000002,"""%1"" %*"`)
	want := []string{"", "0x00000002", `"%1" %*`}
	if len(got) != len(want) {
		t.Fatalf("splitINFCSV() = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitINFCSV()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseINFExecutableCommandPreservesTargetQuotes(t *testing.T) {
	inf, err := parseINF("[AddReg]\nHKCR,exefile\\shell\\open\\command,\"\",0x00000002,\"\"\"%1\"\" %*\"\n")
	if err != nil {
		t.Fatal(err)
	}
	section, ok, err := infSection(inf, "AddReg")
	if err != nil || !ok {
		t.Fatalf("AddReg section: found=%t err=%v", ok, err)
	}
	row, ok, err := section.Get(starlark.String("HKCR,exefile\\shell\\open\\command,\"\",0x00000002,\"\"\"%1\"\" %*\""))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("unexpected unparsed row key: %v", row)
	}
	rows, ok, err := section.Get(starlark.String("@0"))
	if err != nil || !ok {
		t.Fatalf("anonymous row: found=%t err=%v", ok, err)
	}
	list := rows.(*starlark.List)
	if got, _ := starlark.AsString(list.Index(4)); got != `"%1" %*` {
		t.Fatalf("command = %q, want %q", got, `"%1" %*`)
	}
}

func TestParseINFPreservesRootBackslashValue(t *testing.T) {
	inf, err := parseINF(`
[SetupData]
SetupSourcePath = \
MajorVersion = 4

[Directories]
d1 = \
`)
	if err != nil {
		t.Fatal(err)
	}
	setup, ok, err := infSection(inf, "SetupData")
	if err != nil || !ok {
		t.Fatalf("SetupData section: found=%t err=%v", ok, err)
	}
	for name, want := range map[string]string{
		"SetupSourcePath": `\`,
		"MajorVersion":    "4",
	} {
		value, found, err := setup.Get(starlark.String(name))
		if err != nil || !found {
			t.Fatalf("%s: found=%t err=%v", name, found, err)
		}
		row := value.(*starlark.List)
		if got := firstInfString(row.Index(0)); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	directories, ok, err := infSection(inf, "Directories")
	if err != nil || !ok {
		t.Fatalf("Directories section: found=%t err=%v", ok, err)
	}
	value, found, err := directories.Get(starlark.String("d1"))
	if err != nil || !found {
		t.Fatalf("d1: found=%t err=%v", found, err)
	}
	if got := firstInfString(value.(*starlark.List).Index(0)); got != `\` {
		t.Fatalf("d1 = %q, want root backslash", got)
	}
}

func TestParseINFJoinsIndentedContinuationValues(t *testing.T) {
	inf, err := parseINF(`
[AddReg]
HKLM,Software\Example,Data,0x00000003,\
    01,02,03,\
    04
`)
	if err != nil {
		t.Fatal(err)
	}
	section, ok, err := infSection(inf, "AddReg")
	if err != nil || !ok {
		t.Fatalf("AddReg section: found=%t err=%v", ok, err)
	}
	value, found, err := section.Get(starlark.String("@0"))
	if err != nil || !found {
		t.Fatalf("continued row: found=%t err=%v", found, err)
	}
	row := value.(*starlark.List)
	if row.Len() != 8 {
		t.Fatalf("continued row length = %d, want 8: %v", row.Len(), row)
	}
	for index, want := range []string{"01", "02", "03", "04"} {
		if got := firstInfString(row.Index(index + 4)); got != want {
			t.Fatalf("continued value %d = %q, want %q", index, got, want)
		}
	}
}

func TestParseINFSkipsLegacyHashCommentLines(t *testing.T) {
	inf, err := parseINF(`
[Directories]
# Legacy setup metadata uses hash-prefixed comments.
d1 = \
`)
	if err != nil {
		t.Fatal(err)
	}
	section, ok, err := infSection(inf, "Directories")
	if err != nil || !ok {
		t.Fatalf("Directories section: found=%t err=%v", ok, err)
	}
	if section.Len() != 1 {
		t.Fatalf("Directories entries = %d, want 1: %v", section.Len(), section)
	}
}
