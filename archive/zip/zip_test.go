package ziparchive

import (
	"archive/zip"
	"slices"
	"testing"

	"go.starlark.net/starlark"
)

func TestEntryNameWithoutReadingPayload(t *testing.T) {
	entry := NewEntry(&zip.File{FileHeader: zip.FileHeader{Name: "images/ReactOS.iso", UncompressedSize64: 123}})
	name, err := entry.Attr("name")
	if err != nil || name != starlark.String("images/ReactOS.iso") {
		t.Fatalf("name=%v, error=%v", name, err)
	}
	if !slices.Contains(entry.AttrNames(), "name") || !slices.Contains(entry.AttrNames(), "size") {
		t.Fatal("metadata or file attributes missing")
	}
	if entry.reader != nil || len(entry.data) != 0 {
		t.Fatal("name lookup read archive data")
	}
}
