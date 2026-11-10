package windows

import (
	"bytes"
	"crypto/sha256"
	"sync"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/registry"
	"go.starlark.net/starlark"
)

func TestHiveImageEpochSharingAndDefaultValueUpdate(t *testing.T) {
	tree := newRegistryTree("ROOT")
	setRegistryValue(tree, "/Key", "", registryString(regSZ, "before"))
	data, err := buildRegistryHive(tree)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), data...)
	file, err := newHiveImage("source", data)
	if err != nil {
		t.Fatal(err)
	}
	digest, ok := file.VerifiedSHA256()
	if !ok || digest != sha256.Sum256(original) {
		t.Fatal("incorrect owned digest")
	}
	a, err := hiveBuiltin(nil, nil, starlark.Tuple{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hiveBuiltin(nil, nil, starlark.Tuple{file}, []starlark.Tuple{{starlark.String("snapshot"), starlark.True}})
	if err != nil {
		t.Fatal(err)
	}
	if a.(*registryHive).reader != b.(*registryHive).reader {
		t.Fatal("owned epoch not shared")
	}
	if _, err := file.WriteAt([]byte{0}, 0); err == nil {
		t.Fatal("owned file is writable")
	}
	patches := starlark.NewList([]starlark.Value{exclusionRecord([]string{"Key"},
		starlark.Tuple{starlark.String("name"), starlark.String("")},
		starlark.Tuple{starlark.String("type"), starlark.String("REG_SZ")},
		starlark.Tuple{starlark.String("value"), starlark.String("after")})})
	next, err := patchHiveBuiltin(nil, nil, starlark.Tuple{file, patches}, nil)
	if err != nil {
		t.Fatal(err)
	}
	nextFile := next.(*starfile.ReaderValue)
	nextReader := sharedHiveSnapshot(nextFile)
	if nextReader == a.(*registryHive).reader {
		t.Fatal("new epoch reused old index")
	}
	nextBytes, err := starfile.ReadAll(nextFile)
	if err != nil {
		t.Fatal(err)
	}
	nextDigest, ok := nextFile.VerifiedSHA256()
	if !ok || nextDigest != sha256.Sum256(nextBytes) || nextDigest == digest {
		t.Fatal("stale new-version digest")
	}
	oldBytes, err := starfile.ReadAll(file)
	if err != nil || !bytes.Equal(oldBytes, original) {
		t.Fatal("patch modified prior version")
	}
	key, err := nextReader.LookupParts([]string{"Key"})
	if err != nil || key.ValueCount != 1 {
		t.Fatal("empty-name update created duplicate default value")
	}
	cells, err := nextReader.ValueCells(key)
	if err != nil {
		t.Fatal(err)
	}
	value, err := nextReader.ReadValue(cells[0])
	if err != nil || value.Name != "" || !bytes.Equal(value.Data, registryString(regSZ, "after").data) {
		t.Fatal("wrong default value update")
	}
	for _, option := range []string{"delete_values", "exclude_values"} {
		removed, err := patchHiveBuiltin(nil, nil, starlark.Tuple{nextFile, starlark.NewList(nil)}, []starlark.Tuple{{starlark.String(option), starlark.NewList([]starlark.Value{exclusionRecord([]string{"Key"}, starlark.Tuple{starlark.String("name"), starlark.String("")})})}})
		if err != nil {
			t.Fatal(err)
		}
		h := sharedHiveSnapshot(removed.(starfile.File))
		key, err := h.LookupParts([]string{"Key"})
		if err != nil || key.ValueCount != 0 {
			t.Fatal("default value exclusion failed")
		}
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 20; j++ {
				if _, err := nextReader.LookupParts([]string{"kEy"}); err != nil {
					t.Error(err)
				}
				if got, ok := nextFile.VerifiedSHA256(); !ok || got != nextDigest {
					t.Error("concurrent digest changed")
				}
			}
		}()
	}
	group.Wait()
}

func TestBorrowedHiveNeverSharesMutableEpoch(t *testing.T) {
	data, err := buildRegistryHive(newRegistryTree("ROOT"))
	if err != nil {
		t.Fatal(err)
	}
	source := &starfile.Bytes{Data: data}
	live, err := registry.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := live.VerifiedSHA256(); ok {
		t.Fatal("borrowed source advertises digest")
	}
	wrapped := starfile.NewReader("live", live)
	if sharedHiveSnapshot(wrapped) != nil {
		t.Fatal("borrowed registry view shared as snapshot")
	}
	snapshot, err := hiveBuiltin(nil, nil, starlark.Tuple{wrapped}, []starlark.Tuple{{starlark.String("snapshot"), starlark.True}})
	if err != nil {
		t.Fatal(err)
	}
	reader := snapshot.(*registryHive).reader
	want := sha256.Sum256(data)
	data[0] = 'X'
	got, ok := reader.VerifiedSHA256()
	if !ok || got != want {
		t.Fatal("snapshot digest followed source mutation")
	}
	raw := make([]byte, 4)
	if _, err := reader.ReadAt(raw, 0); err != nil || string(raw) != "regf" {
		t.Fatal("snapshot bytes followed mutation")
	}
}
