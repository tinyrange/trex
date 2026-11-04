package windows

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/registry"
	"go.starlark.net/starlark"
)

func TestHiveSnapshotIsolationAndIndexedLookup(t *testing.T) {
	tree := newRegistryTree("ROOT")
	for i := 0; i < 512; i++ {
		ensureRegistryKeyParts(tree, []string{fmt.Sprintf("Child%04d", i), "Literal/Slash"})
	}
	for _, name := range []string{"K", "S", "Σ"} {
		setRegistryValueParts(tree, []string{name}, "Value", registryString(regSZ, "kept"))
	}
	data, err := buildRegistryHiveWithFormat(tree, registryHiveFormat{major: 1, minor: 5})
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(data)
	source := &starfile.Bytes{Data: data}
	snapshot, err := registry.OpenSnapshot(source, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	live, err := registry.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, parts := range [][]string{{"child0500", "literal/slash"}, {"K"}, {"ſ"}, {"ς"}} {
		a, err := snapshot.LookupParts(parts)
		if err != nil {
			t.Fatal(err)
		}
		b, err := live.LookupParts(parts)
		if err != nil || a != b {
			t.Fatal("snapshot lookup differs", err)
		}
	}
	root, err := snapshot.ReadKey(snapshot.RootCell())
	if err != nil {
		t.Fatal(err)
	}
	children, err := snapshot.ReadSubkeys(root)
	if err != nil {
		t.Fatal(err)
	}
	children[0].Name = "poison"
	again, _ := snapshot.ReadSubkeys(root)
	if again[0].Name == "poison" {
		t.Fatal("mutable child slice aliases cache")
	}
	cell, _ := snapshot.ReadCell(root.Cell)
	cell[0] = 0
	if _, err := snapshot.ReadKey(root.Cell); err != nil {
		t.Fatal("cell aliases owned bytes")
	}
	data[4096+root.Cell+4] = 0
	if _, err := live.ReadKey(root.Cell); err == nil {
		t.Fatal("ordinary view accidentally caches mutable input")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := snapshot.LookupParts([]string{"Child0500", "Literal/Slash"}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if _, err := registry.OpenSnapshot(source, int64(len(data)-1)); err == nil {
		t.Fatal("snapshot ignores byte bound")
	}
	v, err := hiveBuiltin(nil, nil, starlark.Tuple{&starfile.Bytes{Data: original}}, []starlark.Tuple{{starlark.String("snapshot"), starlark.True}})
	if err != nil {
		t.Fatal(err)
	}
	original[0] = 0
	h := v.(*registryHive)
	if _, err := h.lookupParts([]string{"K"}); err != nil {
		t.Fatal(err)
	}
	// Whole-hive projection methods must use the captured file too.
	keys, _ := h.Attr("keys")
	if _, err := starlark.Call(&starlark.Thread{Name: "snapshot"}, keys, nil, nil); err != nil {
		t.Fatal(err)
	}
}
