package repo

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func TestDiffAcrossRepositoriesAndStorageEncodings(t *testing.T) {
	var views []*Workspace
	for _, createTestMode := range []func(string) (*Repository, error){createTest, createTestOptimized} {
		r, err := createTestMode(filepath.Join(t.TempDir(), "r.scs"))
		must(t, err)
		t.Cleanup(func() { r.Close() })
		w := r.Empty()
		must(t, w.Mkdir("d"))
		must(t, w.WriteFile("d/f", bytes.Repeat([]byte("same content"), 600)))
		must(t, w.Symlink("link", "d/f"))
		_, err = w.Publish("main")
		must(t, err)
		views = append(views, w)
	}
	// Body-backed V3 and chunk-backed V2 identities differ; equal bytes must
	// still compare equal, without requiring a common repository or encoding.
	got, err := Diff(context.Background(), views[0], views[1])
	must(t, err)
	if len(got) != 0 {
		t.Fatal(got)
	}
	must(t, views[1].Chmod("d", 0700))
	got, err = Diff(context.Background(), views[0], views[1])
	must(t, err)
	if len(got) != 1 || got[0].Path != "d" || got[0].After.Mode != 0700 {
		t.Fatal(got)
	}
	// Within V3, a page-overlay flush may change storage identity without
	// changing file contents. That too must not report a semantic edit.
	old, err := views[1].Fork()
	must(t, err)
	reader, err := views[1].OpenReader("d/f")
	must(t, err)
	must(t, views[1].WritePages("d/f", reader, reader.Size(), reader.Size(), nil))
	reader.Close()
	got, err = Diff(context.Background(), old, views[1])
	must(t, err)
	if len(got) != 0 {
		t.Fatal(got)
	}
}
