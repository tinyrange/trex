package windows

import (
	"crypto/sha1"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestImageDigestBindingBounds(t *testing.T) {
	file := &starfile.Bytes{Data: []byte("ordinary file")}
	got, err := imageDigestBuiltin(nil, nil, starlark.Tuple{file}, nil)
	want := sha1.Sum(file.Data)
	if err != nil || got != starlark.Bytes(want[:]) {
		t.Fatalf("non-image: %v %v", got, err)
	}
	for _, bound := range []int{-1, 0, len(file.Data) - 1, 512<<20 + 1} {
		if _, err := imageDigestBuiltin(nil, nil, starlark.Tuple{file}, []starlark.Tuple{{starlark.String("maximum_bytes"), starlark.MakeInt(bound)}}); err == nil {
			t.Fatalf("ignored bound %d", bound)
		}
	}
	if _, err := imageDigestBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("abc")}, nil); err == nil {
		t.Fatal("accepted bytes as file")
	}
	if _, err := imageDigestBuiltin(nil, nil, starlark.Tuple{file, starlark.String("unknown")}, nil); err == nil {
		t.Fatal("accepted unsupported hash")
	}
}
