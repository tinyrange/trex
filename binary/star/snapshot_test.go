package star

import (
	"bytes"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func TestBinarySnapshotIndependentRandomAccess(t *testing.T) {
	input := bytes.Repeat([]byte("payload"), 20000)
	source := &starfile.Bytes{Data: bytes.Clone(input)}
	value, err := starlark.Call(&starlark.Thread{}, Builtins()["snapshot"], starlark.Tuple{source}, nil)
	if err != nil {
		t.Fatal(err)
	}
	clear(source.Data)
	file := value.(starfile.File)
	got := make([]byte, 120)
	if _, err := file.ReadAt(got, 65500); err != nil || !bytes.Equal(got, input[65500:65620]) {
		t.Fatalf("chunk boundary: %v", err)
	}
	if _, err := file.WriteAt([]byte{1}, 0); err == nil {
		t.Fatal("snapshot writable")
	}
	for _, args := range []starlark.Tuple{{starlark.String("not a file")}, {source, starlark.MakeInt(-1)}, {source, starlark.MakeInt(3)}} {
		if _, err := binarySnapshotBuiltin(nil, nil, args, nil); err == nil {
			t.Fatal("invalid source/bound accepted", args)
		}
	}
}
