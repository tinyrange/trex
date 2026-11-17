package ckd

import (
	"testing"

	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func TestImageBuiltinPhysicalCountAddressesAndBounds(t *testing.T) {
	b := starlark.NewBuiltin("ckd_image", ImageBuiltin)
	call := func(records []starlark.Value) (starlark.Value, error) {
		tracks := starlark.NewDict(1)
		tracks.SetKey(starlark.MakeInt(2), starlark.NewList(records))
		return starlark.Call(&starlark.Thread{Name: "ckd-image-test"}, b, starlark.Tuple{starlark.MakeInt(2), starlark.MakeInt(2), starlark.MakeInt(64), starlark.MakeInt(0x90)}, []starlark.Tuple{{starlark.String("tracks"), tracks}})
	}
	v, err := call([]starlark.Value{starlark.Tuple{starlark.MakeInt(7), starlark.Bytes("key"), starlark.Bytes("payload")}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := Open(v.(storage.Reader))
	if err != nil {
		t.Fatal(err)
	}
	records, err := d.Track(2)
	if err != nil || len(records) != 1 || records[0].Cylinder != 1 || records[0].Head != 0 || records[0].Number != 7 || string(records[0].Key) != "key" || string(records[0].Data) != "payload" {
		t.Fatalf("Starlark record did not reach native image: %+v %v", records, err)
	}
	for _, bad := range []starlark.Value{
		starlark.Tuple{starlark.MakeInt(256), starlark.Bytes(""), starlark.Bytes("")},
		starlark.Tuple{starlark.MakeInt(1), starlark.String("not bytes"), starlark.Bytes("")},
		starlark.Tuple{starlark.MakeInt(1), starlark.Bytes(string(make([]byte, 256))), starlark.Bytes("")},
		starlark.Tuple{starlark.MakeInt(1), starlark.Bytes(""), starlark.Bytes(string(make([]byte, 65536)))},
		starlark.Tuple{starlark.MakeInt(1), starlark.Bytes(""), starlark.Bytes(string(make([]byte, 44)))},
	} {
		if _, err := call([]starlark.Value{bad}); err == nil {
			t.Fatal("invalid record accepted", bad.Type())
		}
	}
	many := make([]starlark.Value, 7)
	for i := range many {
		many[i] = starlark.Tuple{starlark.MakeInt(i), starlark.Bytes(""), starlark.Bytes("")}
	}
	if _, err := call(many); err == nil {
		t.Fatal("oversized count list accepted")
	}
}
