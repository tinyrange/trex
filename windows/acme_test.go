package windows

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestACMEReferenceExpansionDoesNotConsumeUnknownIDPrefixes(t *testing.T) {
	got := expandACMEReferences(`%2\%20\%F20\%F2`, map[string]string{"2": "dir"}, map[string]string{"2": "file"})
	if got != `dir\%20\%F20\file` {
		t.Fatal(got)
	}
}

func TestACMETablePreservesObjectsAndProvenance(t *testing.T) {
	text := "App Name\tCaf\xe9\r\nObjID\tInstall During Batch Mode\tTitle\tDescr\tType\tData\tBMP Id\tVital\tShared\tDir Chang\tDest Dir\r\n1\tYes\tProduct\t\t Group  \t2 3\t\t\t\t\tC:\\APP\r\n== annotation ==\r\n2\r\n3\t\t\t\tCustomAction\t\"runtime.dll,Register,\"\"a,b\"\"\"\r\n"
	result, err := parseACMETable([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	get := func(d *starlark.Dict, k string) starlark.Value { v, _, _ := d.Get(starlark.String(k)); return v }
	header := get(result, "header").(*starlark.Dict)
	if get(header, "App Name") != starlark.String("Café") {
		t.Fatal(header)
	}
	objects := get(result, "objects").(*starlark.Dict)
	if objects.Len() != 3 {
		t.Fatal(objects)
	}
	row := get(objects, "1").(*starlark.Dict)
	if get(row, "type") != starlark.String("Group") || get(row, "line") != starlark.MakeInt(3) {
		t.Fatal(row)
	}
	row = get(objects, "3").(*starlark.Dict)
	argv := get(row, "arguments").(*starlark.List)
	if argv.Len() != 3 || argv.Index(2) != starlark.String("a,b") {
		t.Fatal(argv)
	}
	if _, err := parseACMETable([]byte(text + "3\t\n")); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatal("duplicate accepted", err)
	}
}

func TestACMEArgumentsWithNameAlternatives(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  []string
	}{
		{`"""C:\APP""<C:\Application>,APP.EXE,1.0"`, []string{`C:\APP<C:\Application>`, "APP.EXE", "1.0"}},
		{`library.dll,Register,"a,b"`, []string{"library.dll", "Register", "a,b"}},
		{`"""LOCAL"",""Software\Example"",""ddeexec"",[FileNew("")],"""""`, []string{"LOCAL", `Software\Example`, "ddeexec", `[FileNew(")]`, ""}},
	} {
		got, err := acmeArguments(tc.input)
		if err != nil || strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%q: %q, %v", tc.input, got, err)
		}
	}
}

func TestACMEPlanRetainsUnknownBranches(t *testing.T) {
	table := &starfile.Bytes{Data: []byte("Batch Mode Root Object ID\t1\nObjID\tInstall During Batch Mode\tTitle\tDescr\tType\tData\tBMP Id\tVital\tShared\tDir Chang\tDest Dir\n1\tYes\t\t\tDepend\t9 ? 2 : 3\n2\tYes\t\t\tCopyFile\tFiles,one\n3\tYes\t\t\tCopyFile\tFiles,two\n9\t\t\t\tCustomAction\tdetect.dll,Detect\n")}
	parsed, err := parseINF("[Files]\none=1,ONE.TXT\ntwo=1,TWO.TXT\n")
	if err != nil {
		t.Fatal(err)
	}
	media := starlark.NewDict(2)
	_ = media.SetKey(starlark.String("ONE.TXT"), &starfile.Bytes{Data: []byte("one")})
	_ = media.SetKey(starlark.String("TWO.TXT"), &starfile.Bytes{Data: []byte("two")})
	value, err := acmePlanBuiltin(&starlark.Thread{}, nil, starlark.Tuple{table, &infFile{json: parsed}, media}, []starlark.Tuple{{starlark.String("target"), starlark.String(`C:\APP`)}})
	if err != nil {
		t.Fatal(err)
	}
	files := acmeGet(value.(*starlark.Dict), "files").(*starlark.List)
	if files.Len() != 2 {
		t.Fatal(files)
	}
	for i, want := range []string{"9", "NOT 9"} {
		conditions := acmeGet(files.Index(i).(*starlark.Dict), "conditions").(*starlark.List)
		if conditions.Len() != 1 || conditions.Index(0) != starlark.String(want) {
			t.Fatal(conditions)
		}
	}
}
