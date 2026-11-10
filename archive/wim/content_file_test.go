package wim

import (
	"bytes"
	"github.com/tinyrange/trex/filesystem"
	"go.starlark.net/starlark"
	"io"
	"testing"
)

func TestAppliedContentPreservesMetadataAfterRelease(t *testing.T) {
	meta := append(make([]byte, 8), legacyTestRecord("Long filename.txt", "LONGFI~1.TXT", 0x20, 0, 2)...)
	meta = append(meta, legacyTestStream("", 1)...)
	meta = append(meta, legacyTestStream("Zone.Identifier", 2)...)
	meta = append(meta, make([]byte, 8)...)
	a, err := Open(&countingWIMFile{data: legacyTestArchive(meta, []byte("main"), []byte("zone"))})
	if err != nil {
		t.Fatal(err)
	}
	original, err := a.OpenFile("/image1/Long filename.txt")
	if err != nil {
		t.Fatal(err)
	}
	target := filesystem.New()
	if _, err = a.applyBuiltin(nil, nil, starlark.Tuple{target}, nil); err != nil {
		t.Fatal(err)
	}
	applied := target.Snapshot().Files["/Long filename.txt"].File
	if _, ok := applied.(*contentFile); !ok {
		t.Fatalf("applied reader %T", applied)
	}
	a.ReleaseReadCaches()
	got, err := io.ReadAll(io.NewSectionReader(applied, 0, applied.Size()))
	if err != nil || string(got) != "main" {
		t.Fatalf("read: %q %v", got, err)
	}
	for _, name := range []string{"metadata", "resource", "streams"} {
		want, err := original.(starlark.HasAttrs).Attr(name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := applied.(starlark.HasAttrs).Attr(name)
		if err != nil || got.String() != want.String() {
			t.Fatalf("%s: %v want %v (%v)", name, got, want, err)
		}
	}
	verify, err := applied.(starlark.HasAttrs).Attr("verify")
	if err != nil {
		t.Fatal(err)
	}
	result, err := starlark.Call(&starlark.Thread{}, verify, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := result.(starlark.HasAttrs).Attr("valid")
	if err != nil || valid != starlark.True {
		t.Fatalf("verify: %v %v", valid, err)
	}
}

func TestAppliedSolidContentSharesBlobIdentity(t *testing.T) {
	a, source, files, plain := prefetchFixture()
	original := files["/image1/late"]
	content := a.newContentFile(original.entry)
	got := make([]byte, 1000)
	if _, err := original.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	reads := source.reads
	source.data = nil
	if _, err := content.ReadAt(got, 0); err != nil || !bytes.Equal(got, plain[40000:41000]) {
		t.Fatalf("cache identity: %v", err)
	}
	if source.reads != reads {
		t.Fatal("applied reader missed existing blob")
	}
	n, err := content.ReadAt(got, 999)
	if n != 1 || err != io.EOF {
		t.Fatalf("EOF: %d %v", n, err)
	}
}
