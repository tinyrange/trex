package json

import (
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

func TestJSONDecodePreservesValuesAndIntegerPrecision(t *testing.T) {
	value, err := jsonDecodeBuiltin(nil, nil, starlark.Tuple{starlark.String(`{"large":18446744073709551617,"items":[true,null,1.5]}`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dict := value.(*starlark.Dict)
	large, found, err := dict.Get(starlark.String("large"))
	if err != nil || !found || large.String() != "18446744073709551617" {
		t.Fatalf("large = %v, %v, %v", large, found, err)
	}
	items, found, err := dict.Get(starlark.String("items"))
	if err != nil || !found || items.(*starlark.List).Len() != 3 {
		t.Fatalf("items = %v, %v, %v", items, found, err)
	}
}

func TestJSONDecodeRejectsLimitsAndTrailingValues(t *testing.T) {
	if _, err := jsonDecodeBuiltin(nil, nil, starlark.Tuple{starlark.String(`{"value":1}`)}, []starlark.Tuple{
		{starlark.String("maximum"), starlark.MakeInt(4)},
	}); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("limit error = %v", err)
	}
	if _, err := jsonDecodeBuiltin(nil, nil, starlark.Tuple{starlark.String(`{} {}`)}, nil); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("trailing error = %v", err)
	}
}
