package windows

import (
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/dmr"
	"go.starlark.net/starlark"
)

func TestDMRSectionsInspection(t *testing.T) {
	// Unknown and repeated tags must remain visible, in source order.
	data, err := dmr.EncodeContainer([]dmr.Section{{Tag: 123, Data: []byte{1, 2, 3, 4}}, {Tag: 123, Data: []byte{5, 6, 7, 8}}})
	if err != nil {
		t.Fatal(err)
	}
	env := Builtins()
	env["input"] = &starfile.Bytes{Data: data}
	got, err := starlark.Eval(&starlark.Thread{Name: "inspect"}, "test.star", "dmr_sections(input)", env)
	if err != nil {
		t.Fatal(err)
	}
	rows := got.(*starlark.List)
	if rows.Len() != 2 {
		t.Fatal(rows)
	}
	for i := 0; i < rows.Len(); i++ {
		row := rows.Index(i).(*starlark.Dict)
		tag, _, _ := row.Get(starlark.String("tag"))
		payload, _, _ := row.Get(starlark.String("data"))
		if tag.String() != "123" || payload.(*starfile.Bytes).Data[0] != byte(1+4*i) {
			t.Fatal(row)
		}
	}
	for _, expr := range []string{"dmr_sections(1)", "dmr_sections(input,max_bytes=36)", "dmr_sections(input,max_bytes=-1)"} {
		if _, err := starlark.Eval(&starlark.Thread{Name: "invalid"}, "test.star", expr, env); err == nil {
			t.Fatalf("accepted %s", expr)
		}
	}
	corrupt := append([]byte(nil), data...)
	corrupt[32] = 0 // First payload offset now overlaps the header.
	env["input"] = &starfile.Bytes{Data: corrupt}
	if _, err := starlark.Eval(&starlark.Thread{Name: "invalid"}, "test.star", "dmr_sections(input)", env); err == nil {
		t.Fatal("accepted overlapping section")
	}
}
