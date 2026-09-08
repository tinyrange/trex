package imports

import (
	starvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
	"testing"
)

func TestNamedPreservesOrderDuplicatesAndOwnership(t *testing.T) {
	var records []starlark.Value
	for _, name := range []string{"Run", "Other", "RUN", ""} {
		records = append(records, starvalue.NewRecord(starlark.StringDict{"name": starlark.String(name)}))
	}
	index := New(starlark.NewList(records))
	names := starlark.NewDict(1)
	names.SetKey(starlark.String("run"), starlark.MakeInt(2))
	for i := 0; i < 2; i++ {
		value, err := index.Named(starlark.Tuple{names}, nil)
		if err != nil {
			t.Fatal(err)
		}
		list := value.(*starlark.List)
		if list.Len() != 2 || list.Index(0) != records[0] || list.Index(1) != records[2] {
			t.Fatalf("unexpected result: %v", list)
		}
		if err := list.SetIndex(0, starlark.None); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := index.Named(starlark.Tuple{starlark.NewList([]starlark.Value{starlark.MakeInt(1)})}, nil); err == nil {
		t.Fatal("non-string accepted")
	}
}
