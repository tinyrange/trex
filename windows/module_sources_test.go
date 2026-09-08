package windows

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func TestModuleSourcesOrderExclusionsAndLazyFiles(t *testing.T) {
	first := &countingPEFile{Bytes: &starfile.Bytes{Data: []byte("not a PE")}}
	files := starlark.NewDict(0)
	for _, item := range []struct {
		path  string
		value starlark.Value
	}{
		{"C:\\First\\Example.DLL", first},
		{"C:/Second/example.dll", starlark.None},
		{"C:/Kernel32.DLL", starlark.None},
		{"C:/ordinary.exe", starlark.None},
		{"C:/extensionless", starlark.String("retained")},
		{"C:/folder.with.dot/Last.dll", starlark.String("last")},
	} {
		_ = files.SetKey(starlark.String(item.path), item.value)
	}
	value, err := moduleSourcesBuiltin(nil, nil, starlark.Tuple{files}, []starlark.Tuple{{starlark.String("exclude"), starlark.Tuple{starlark.String("KERNEL32")}}})
	if err != nil {
		t.Fatal(err)
	}
	out := value.(*starlark.Dict)
	want := []string{"example.dll", "extensionless.dll", "last.dll"}
	if out.Len() != len(want) {
		t.Fatalf("sources = %s", out)
	}
	for i, key := range out.Keys() {
		if key != starlark.String(want[i]) {
			t.Fatalf("order = %v", out.Keys())
		}
	}
	selected, _, _ := out.Get(starlark.String("example.dll"))
	if selected != first || first.reads != 0 {
		t.Fatal("selection read/replaced first source")
	}
	_ = out.SetKey(starlark.String("extra"), starlark.None)
	if files.Len() != 6 {
		t.Fatal("source mapping was mutated")
	}
}
