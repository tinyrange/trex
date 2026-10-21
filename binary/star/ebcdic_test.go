package star

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestIBM037StringsAndInputBudget(t *testing.T) {
	// National character é must not be split or counted as two UTF-8 bytes.
	raw := starlark.Bytes("\x00\xc1\x51\xc2\x00\xc3\xc4\x00")
	got, err := binaryStringsBuiltin(nil, nil, starlark.Tuple{raw}, []starlark.Tuple{{starlark.String("encoding"), starlark.String("ibm037")}, {starlark.String("minimum"), starlark.MakeInt(3)}})
	if err != nil || got.String() != `["AéB"]` {
		t.Fatal(got, err)
	}
	if _, err := binaryStringsBuiltin(nil, nil, starlark.Tuple{raw}, []starlark.Tuple{{starlark.String("maximum"), starlark.MakeInt(2)}}); err == nil {
		t.Fatal("byte input exceeded budget")
	}
}
