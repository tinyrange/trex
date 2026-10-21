package cc

import (
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestDisassemblyRelativeAndTruncated(t *testing.T) {
	v, err := decodeInstructions([]byte{0xe8, 1, 0, 0, 0, 0x90, 0x48, 0xb8, 1}, 0x1000, 64)
	if err != nil {
		t.Fatal(err)
	}
	rows := v.(*starlark.List)
	if rows.Len() != 3 {
		t.Fatal(v)
	}
	text, _, _ := rows.Index(0).(*starlark.Dict).Get(starlark.String("text"))
	if !strings.Contains(text.(starlark.String).GoString(), "0x1006") {
		t.Fatalf("wrong relative target %s", text)
	}
	last := rows.Index(2).(*starlark.Dict)
	a, _, _ := last.Get(starlark.String("address"))
	msg, found, _ := last.Get(starlark.String("error"))
	n, _ := a.(starlark.Int).Uint64()
	if n != 0x1006 || !found || msg == nil {
		t.Fatalf("truncated terminal instruction not identified %v", last)
	}
}
