package cc

import (
	"go.starlark.net/starlark"
	"testing"
	"time"
)

func TestP390BackendOptionsValidateWithoutStartingGuest(t *testing.T) {
	b := Builtins()["backend"]
	call := func(opts ...starlark.Tuple) (starlark.Value, error) {
		return starlark.Call(&starlark.Thread{Name: "p390-options"}, b, nil, opts)
	}
	epoch := "1985-01-01T08:00:00Z"
	enabled := starlark.Tuple{starlark.String("p390"), starlark.True}
	compat := starlark.Tuple{starlark.String("p390_s370"), starlark.True}
	clock := starlark.Tuple{starlark.String("p390_start"), starlark.String(epoch)}
	for _, opts := range [][]starlark.Tuple{{compat}, {clock}, {enabled, {starlark.String("p390_start"), starlark.String("not-an-epoch")}}} {
		if _, err := call(opts...); err == nil {
			t.Fatal("invalid mainframe options accepted", opts)
		}
	}
	value, err := call(enabled, compat, clock)
	if err != nil {
		t.Fatal(err)
	}
	backend := value.(*Backend)
	want, _ := time.Parse(time.RFC3339, epoch)
	if !backend.P390 || !backend.P390S370 || !backend.P390Start.Equal(want) {
		t.Fatal("CPU/clock options not retained", backend)
	}
}
