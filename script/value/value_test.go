package value

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestUnsignedArchitecturalEvent(t *testing.T) {
	v, e := Starlark(map[string]any{"pc": uint64(0xfffffc00002abf50), "status": uint32(0x93090006)})
	if e != nil {
		t.Fatal(e)
	}
	pc, _, e := v.(*starlark.Dict).Get(starlark.String("pc"))
	if e != nil {
		t.Fatal(e)
	}
	x, ok := pc.(starlark.Int).Uint64()
	if !ok || x != 0xfffffc00002abf50 {
		t.Fatal("lost high address bits")
	}
	native, e := Native(v)
	if e != nil || native.(map[string]any)["pc"] != uint64(0xfffffc00002abf50) {
		t.Fatalf("round trip: %v %v", native, e)
	}
}
