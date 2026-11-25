package windows

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func TestRegistry31SourceKeyOnlyDiffersFromEmpty(t *testing.T) {
	source := &starfile.Bytes{Data: []byte("REGEDIT\r\nHKEY_CLASSES_ROOT\\KeyOnly\r\nHKEY_CLASSES_ROOT\\Empty = \r\nHKEY_CLASSES_ROOT\\KeyOnly\\child = value\r\n")}
	entries := starlark.NewDict(1)
	if err := entries.SetKey(starlark.String("Override"), starlark.None); err != nil {
		t.Fatal(err)
	}
	value, err := registry31Builtin(nil, nil, starlark.Tuple{entries}, []starlark.Tuple{{starlark.String("sources"), starlark.NewList([]starlark.Value{source})}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := starfile.ReadAll(value.(starfile.File))
	if err != nil {
		t.Fatal(err)
	}
	got, err := readRegistry31(data)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := got[`.classes\keyonly`]; !ok || v != nil {
		t.Fatalf("key-only=%v %v", v, ok)
	}
	if v, ok := got[`.classes\empty`]; !ok || v == nil || *v != "" {
		t.Fatalf("explicit empty=%v %v", v, ok)
	}
	if v, ok := got[`.classes\override`]; !ok || v != nil {
		t.Fatalf("None override=%v %v", v, ok)
	}
	if v := got[`.classes\keyonly\child`]; v == nil || *v != "value" {
		t.Fatal("key-only child lost")
	}
}
