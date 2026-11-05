package windows

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestStandaloneTypeLibraryBinding(t *testing.T) {
	data := testMSFTTypeLib(t)
	result, err := typeLibraryBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(data)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	row := result.(*starlark.Dict)
	guid, found, err := row.Get(starlark.String("guid"))
	if err != nil || !found || guid != starlark.String("{A5064420-D541-11D4-9523-00B0D022CA64}") {
		t.Fatalf("identity: %v %v", guid, err)
	}
	for _, bad := range [][]byte{nil, []byte("MZxx"), data[:len(data)-1]} {
		if _, err := typeLibraryBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(bad)}, nil); err == nil {
			t.Fatal("accepted invalid standalone library")
		}
	}
}
