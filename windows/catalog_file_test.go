package windows

import (
	"bytes"
	"sync"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestCatalogOwnedParse(t *testing.T) {
	data := signedCatalogFixture(t, signingTestIdentity(t), true, false)
	original := bytes.Clone(data)
	source := &starfile.Bytes{Data: data}
	value, err := catalogBuiltin(nil, nil, starlark.Tuple{source}, nil)
	if err != nil {
		t.Fatal(err)
	}
	handle := value.(*parsedCatalog)
	data[0] = 0
	read, err := starfile.ReadAll(handle)
	if err != nil || !bytes.Equal(read, original) {
		t.Fatal("catalog aliases input", err)
	}
	if _, err := handle.WriteAt([]byte{0}, 0); err == nil {
		t.Fatal("writable snapshot")
	}
	same, err := catalogBuiltin(nil, nil, starlark.Tuple{handle}, nil)
	if err != nil || same != handle {
		t.Fatal("snapshot was not reused")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := handle.signature(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for _, builtin := range []func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error){catalogIndexBuiltin, catalogSignatureBuiltin} {
		a, err := builtin(nil, nil, starlark.Tuple{handle}, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, err := builtin(nil, nil, starlark.Tuple{starlark.Bytes(original)}, nil)
		if err != nil || a.String() != b.String() {
			t.Fatal("snapshot differs from ordinary input", err)
		}
		// A consumer's list mutation must not poison the cached native facts.
		var list starlark.Value
		if dict, ok := a.(*starlark.Dict); ok {
			list, _, _ = dict.Get(starlark.String("sha256"))
		} else {
			list, _ = a.(starlark.HasAttrs).Attr("certificates")
		}
		if err := list.(*starlark.List).Clear(); err != nil {
			t.Fatal(err)
		}
		again, err := builtin(nil, nil, starlark.Tuple{handle}, nil)
		if err != nil || again.String() != b.String() {
			t.Fatal("mutable result poisoned cache", err)
		}
	}
	bad := bytes.Clone(original)
	at := bytes.Index(bad, bytes.Repeat([]byte{0x5a}, 32))
	bad[at] ^= 1
	tampered, err := catalogBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(bad)}, nil)
	if err != nil {
		t.Fatal(err)
	} // Membership parsing alone is not authentication.
	for i := 0; i < 2; i++ {
		if _, err := catalogSignatureBuiltin(nil, nil, starlark.Tuple{tampered}, nil); err == nil {
			t.Fatal("accepted altered signed membership")
		}
	}
}

func TestAssemblyManifestLazyProjectionOwnership(t *testing.T) {
	source := starlark.Bytes(`<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="example" version="1.0.0.0" processorArchitecture="amd64"/><file name="example.dll"/></assembly>`)
	a, err := assemblyManifestBuiltin(nil, nil, starlark.Tuple{source}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := assemblyManifestBuiltin(nil, nil, starlark.Tuple{source}, nil)
	if err != nil {
		t.Fatal(err)
	}
	av, bv := a.(*assemblyManifestValue), b.(*assemblyManifestValue)
	if len(av.fields) != 0 {
		t.Fatal("eager projections")
	}
	files, _ := av.Attr("files")
	if err := files.(*starlark.List).Clear(); err != nil {
		t.Fatal(err)
	}
	other, _ := bv.Attr("files")
	if other.(*starlark.List).Len() != 1 {
		t.Fatal("views alias")
	}
	av.Freeze()
	lazy, _ := av.Attr("identity")
	if err := lazy.(*starlark.List).Clear(); err == nil {
		t.Fatal("late projection not frozen")
	}
	bv.Freeze()
	if err := other.(*starlark.List).Clear(); err == nil {
		t.Fatal("existing projection not frozen")
	}
	// Frozen values can cross Starlark threads before any optional field is
	// projected. Late lazy materialization must be race-free and frozen.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, err := bv.Attr("references")
			if err != nil {
				t.Error(err)
				return
			}
			if err := value.(*starlark.List).Clear(); err == nil {
				t.Error("mutable shared projection")
			}
		}()
	}
	wg.Wait()
}
