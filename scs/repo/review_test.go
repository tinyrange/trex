package repo

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestDiffAndExportRepresentNativeChanges(t *testing.T) {
	r, _ := newRepo(t)
	before := r.Empty()
	must(t, before.WriteFile("binary", []byte{0, 1, 2, 255}))
	must(t, before.WriteFile("exec", []byte("run")))
	must(t, before.WriteFile("gone", []byte("deleted")))
	must(t, before.WriteFile("unchanged", []byte("same")))
	must(t, before.Symlink("link", "binary"))
	after, err := before.Fork()
	must(t, err)
	must(t, after.WriteFile("binary", []byte{0, 1, 3, 255}))
	must(t, after.Chmod("exec", 0755))
	must(t, after.Delete("gone"))
	must(t, after.Mkdir("empty"))
	must(t, after.Chmod("empty", 0700))
	must(t, after.Delete("link"))
	must(t, after.Symlink("link", "../../outside"))
	must(t, after.SetTimes("unchanged", Times{M: 1234567890123456789}))
	// Deliberately awkward names must not become ambiguous output or traversals.
	must(t, after.WriteFile("space newline\nname", []byte("new")))
	changes, err := Diff(context.Background(), before, after)
	must(t, err)
	var got []string
	for _, c := range changes {
		got = append(got, c.Status+":"+c.Path)
	}
	want := []string{"modified:binary", "added:empty", "modified:exec", "deleted:gone", "modified:link", "added:space newline\nname"}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
	if changes[0].Before.SHA256 == changes[0].After.SHA256 || len(changes[0].After.SHA256) != 64 {
		t.Fatal("binary diff hash")
	}
	if changes[4].After.Target != "../../outside" {
		t.Fatal("link diff")
	}
	var archive bytes.Buffer
	must(t, ExportTar(context.Background(), after, &archive))
	tr := tar.NewReader(&archive)
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		must(t, err)
		seen[h.Name] = true
		if h.Uid != 0 || h.Gid != 0 {
			t.Fatal("ownership")
		}
		switch h.Name {
		case "binary":
			data, err := io.ReadAll(tr)
			must(t, err)
			if !bytes.Equal(data, []byte{0, 1, 3, 255}) {
				t.Fatal(data)
			}
		case "empty/":
			if h.Typeflag != tar.TypeDir || h.Mode != 0700 {
				t.Fatal(h)
			}
		case "exec":
			if h.Mode != 0755 {
				t.Fatal(h)
			}
		case "link":
			if h.Typeflag != tar.TypeSymlink || h.Linkname != "../../outside" {
				t.Fatal(h)
			}
		case "unchanged":
			if h.ModTime.UnixNano() != 1234567890123456789 {
				t.Fatal(h.ModTime)
			}
		case "space newline\nname":
		default:
			t.Fatal("unexpected archive entry", h.Name)
		}
	}
	if len(seen) != 6 {
		t.Fatal(seen)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Diff(ctx, before, after); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := ExportTar(ctx, after, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestExportPropagatesWriteFailure(t *testing.T) {
	r, _ := newRepo(t)
	w := r.Empty()
	must(t, w.WriteFile("f", []byte("data")))
	if err := ExportTar(context.Background(), w, brokenWriter{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}
