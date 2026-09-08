package windows

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestPEARM64DisasmRelativeAndTruncated(t *testing.T) {
	// BL +8; ADRP x0,+0 (relative to the page, not the instruction); one tail byte.
	rows := peDisasmARM64([]byte{2, 0, 0, 0x94, 0, 0, 0, 0x90, 0xff}, 0x1234)
	if rows.Len() != 3 {
		t.Fatal(rows)
	}
	for index, want := range []int64{0x123c, 0x1000} {
		row := rows.Index(index).(*starlark.Dict)
		args, _, _ := row.Get(starlark.String("operands"))
		list := args.(*starlark.List)
		arg := list.Index(list.Len() - 1).(*starlark.Dict)
		target, _, _ := arg.Get(starlark.String("target"))
		got, _ := target.(starlark.Int).Int64()
		if got != want {
			t.Fatalf("row %d target=%x want=%x", index, got, want)
		}
	}
	tail := rows.Index(2).(*starlark.Dict)
	size, _, _ := tail.Get(starlark.String("size"))
	if size.String() != "1" {
		t.Fatal(tail)
	}
}
