package star

import (
	"bytes"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

type countedSnapshotSource struct {
	starfile.Bytes
	reads int
}

func (f *countedSnapshotSource) ReadAt(p []byte, off int64) (int, error) {
	f.reads++
	return f.Bytes.ReadAt(p, off)
}

func TestSnapshotManyIndependentAcrossSharedCacheEviction(t *testing.T) {
	a := &countedSnapshotSource{Bytes: starfile.Bytes{Data: bytes.Repeat([]byte("alpha"), 30000)}}
	b := &countedSnapshotSource{Bytes: starfile.Bytes{Data: bytes.Repeat([]byte("bravo"), 30000)}}
	expected := [][]byte{bytes.Clone(a.Data), bytes.Clone(b.Data)}
	values := starlark.NewList([]starlark.Value{a, b})
	result, err := binarySnapshotManyBuiltin(nil, nil, starlark.Tuple{values, starlark.MakeInt(300000), starlark.MakeInt(65536)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	clear(a.Data)
	clear(b.Data)
	reads := a.reads + b.reads
	files := result.(*starlark.List)
	for i := 0; i < 12; i++ {
		j := i % 2
		off := int64((i * 31777) % 149900)
		got := make([]byte, 100)
		if _, err := files.Index(j).(starfile.File).ReadAt(got, off); err != nil || !bytes.Equal(got, expected[j][off:off+100]) {
			t.Fatalf("random read %d: %v", i, err)
		}
	}
	if a.reads+b.reads != reads {
		t.Fatal("snapshot retained source")
	}
}

func TestSnapshotManyValidatesWholeBatchBeforeReading(t *testing.T) {
	a := &countedSnapshotSource{Bytes: starfile.Bytes{Data: make([]byte, 10)}}
	for _, args := range []starlark.Tuple{
		{starlark.NewList([]starlark.Value{a, a}), starlark.MakeInt(19), starlark.MakeInt(0)},
		{starlark.NewList([]starlark.Value{a, starlark.String("invalid")})},
		{starlark.NewList([]starlark.Value{a}), starlark.MakeInt(20), starlark.MakeInt(21)},
	} {
		if _, err := binarySnapshotManyBuiltin(nil, nil, args, nil); err == nil {
			t.Fatal("invalid batch accepted")
		}
		if a.reads != 0 {
			t.Fatal("invalid batch read source")
		}
	}
}
