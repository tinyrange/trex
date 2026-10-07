package star

import (
	"github.com/tinyrange/trex/binary/plist"
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestPlistAdapterBudgetsAndCycles(t *testing.T) {
	for _, value := range []starlark.Value{starlark.String("abcd"), starlark.Bytes("abcd")} {
		budget := plistBudget{bytes: plist.MaxBytes - 3}
		if _, err := plistNative(value, 0, &budget); err == nil {
			t.Fatal("accepted oversized leaf before copying")
		}
	}
	budget := plistBudget{nodes: 99999}
	if _, err := plistNative(starlark.NewList([]starlark.Value{starlark.True}), 0, &budget); err == nil {
		t.Fatal("accepted container beyond remaining node budget")
	}
	dictionary := starlark.NewDict(1)
	if err := dictionary.SetKey(starlark.String("long-key"), starlark.True); err != nil {
		t.Fatal(err)
	}
	budget = plistBudget{bytes: plist.MaxBytes - 7}
	if _, err := plistNative(dictionary, 0, &budget); err == nil {
		t.Fatal("dictionary key did not count towards byte budget")
	}
	cycle := starlark.NewList(nil)
	if err := cycle.Append(cycle); err != nil {
		t.Fatal(err)
	}
	budget = plistBudget{}
	if _, err := plistNative(cycle, 0, &budget); err == nil {
		t.Fatal("accepted recursive list")
	}
	shared := starlark.Bytes(strings.Repeat("x", 65536))
	items := make([]starlark.Value, 1025)
	for i := range items {
		items[i] = shared
	}
	budget = plistBudget{}
	if _, err := plistNative(starlark.NewList(items), 0, &budget); err == nil {
		t.Fatal("shared leaves bypassed aggregate byte limit")
	}
}

func TestPlistAdapterTypedRoundTrip(t *testing.T) {
	original := starlark.NewDict(2)
	if err := original.SetKey(starlark.String("data"), starlark.Bytes("\x00\xff")); err != nil {
		t.Fatal(err)
	}
	if err := original.SetKey(starlark.String("list"), starlark.NewList([]starlark.Value{starlark.True, starlark.MakeInt(-1), starlark.String("é")})); err != nil {
		t.Fatal(err)
	}
	encoded, err := plistEncodeBuiltin(nil, nil, starlark.Tuple{original}, nil)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := plistBuiltin(nil, nil, starlark.Tuple{encoded}, nil)
	if err != nil {
		t.Fatal(err)
	}
	equal, err := starlark.Equal(original, decoded)
	if err != nil || !equal {
		t.Fatalf("typed round trip: %v %v", decoded, err)
	}
}
