package star

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestPowerPCBuiltinAddressesAndBounds(t *testing.T) {
	thread := &starlark.Thread{Name: "powerpc-test"}
	got, err := powerPCInstructionsBuiltin(thread, nil, starlark.Tuple{starlark.Bytes("\x4b\x7f\x68\xc2")}, []starlark.Tuple{{starlark.String("size"), starlark.MakeInt(4)}, {starlark.String("address"), starlark.MakeUint64(0xffffffffff100000)}})
	if err != nil {
		t.Fatal(err)
	}
	list, ok := got.(*starlark.List)
	if !ok || list.Len() != 1 {
		t.Fatal(got)
	}
	dict := list.Index(0).(*starlark.Dict)
	target, found, err := dict.Get(starlark.String("target"))
	if err != nil || !found {
		t.Fatal(target, err)
	}
	var addr uint64
	if err := starlark.AsInt(target, &addr); err != nil || addr != 0xffffffffff7f68c0 {
		t.Fatal(target, err)
	}
	if _, err := powerPCInstructionsBuiltin(thread, nil, starlark.Tuple{starlark.Bytes("\x00\x00\x00\x00")}, nil); err == nil {
		t.Fatal("default range exceeded source without failure")
	}
}
