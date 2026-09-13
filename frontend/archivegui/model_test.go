package archivegui

import (
	"archive/zip"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

func zipBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, data := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func fixture(t *testing.T) *auto.Node {
	binary := make([]byte, 256)
	for i := range binary {
		binary[i] = byte(i)
	}
	inner := zipBytes(t, map[string][]byte{"docs/readme.txt": []byte("Hello from the inner archive!\n"), "binary.bin": binary})
	outer := zipBytes(t, map[string][]byte{"inner.zip": inner, "empty.txt": {}, "large.txt": bytes.Repeat([]byte("x"), previewLimit+10)})
	return auto.Directory("test", func() ([]*auto.Node, error) {
		return []*auto.Node{auto.Open(&starfile.Bytes{Data: outer}, "outer.zip", auto.Options{})}, nil
	}, auto.Options{})
}

func TestNestedArchiveNavigationAndPreview(t *testing.T) {
	root := fixture(t)
	for _, name := range []string{"/", "/outer.zip", "/outer.zip/inner.zip", "/outer.zip/inner.zip/docs"} {
		loc, err := readLocation(root, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(loc.children) == 0 {
			t.Fatalf("empty directory %s", name)
		}
	}
	loc, err := readLocation(root, "/outer.zip/inner.zip/docs/readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(loc.preview, "\n"), "Hello from the inner archive!") {
		t.Fatal(loc)
	}
	if len(loc.ancestors) != 4 {
		t.Fatalf("address jump lost ancestors: %v", loc.ancestors)
	}
	loc, err = readLocation(root, "/outer.zip/inner.zip/binary.bin")
	if err != nil || loc.format != "Hex preview" {
		t.Fatal(loc, err)
	}
	loc, err = readLocation(root, "/outer.zip/large.txt")
	if err != nil || !strings.Contains(loc.format, "first 65536 bytes") || len(loc.preview[0]) != previewLimit {
		t.Fatal(loc.format, err)
	}
	loc, err = readLocation(root, "/outer.zip/empty.txt")
	if err != nil || len(loc.preview) != 1 {
		t.Fatal(loc, err)
	}
	if _, err = readLocation(root, "/outer.zip/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestListingDoesNotReadFileBytes(t *testing.T) {
	nodes := []*auto.Node{auto.Open(noRead{}, "Z.zip", auto.Options{}), auto.Directory("Folder", nil, auto.Options{}), auto.Open(noRead{}, "a.txt", auto.Options{})}
	got := rows(nodes, "", 0, true)
	if got[0].Name() != "Folder" || got[1].Name() != "Z.zip" {
		t.Fatal(got)
	}
	got = rows(nodes, ".ZIP", 1, false)
	if len(got) != 1 || got[0].Name() != "Z.zip" {
		t.Fatal(got)
	}
}

type noRead struct{}

func (noRead) Size() int64                       { return 42 }
func (noRead) ReadAt([]byte, int64) (int, error) { panic("listing read file contents") }

func TestNativeSourceReadOnlyAndLifecycle(t *testing.T) {
	dir := t.TempDir()
	data := zipBytes(t, map[string][]byte{"readme.txt": []byte("native reader")})
	if err := os.WriteFile(filepath.Join(dir, "test.zip"), data, 0600); err != nil {
		t.Fatal(err)
	}
	s, root, err := OpenDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	loc, err := readLocation(root, "/test.zip/readme.txt")
	if err != nil || loc.preview[0] != "native reader" {
		t.Fatal(loc, err)
	}
	if len(s.files) != 1 {
		t.Fatal("lazy file not retained", len(s.files))
	}
	n, err := root.Resolve("test.zip")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = n.Reader().ReadAt(make([]byte, 1), 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "test.zip"))
	if err != nil || !bytes.Equal(after, data) {
		t.Fatal("source changed", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("unexpected extracted files", err)
	}
}

func TestNavigationFailurePreservesHistory(t *testing.T) {
	b := newBrowser(fixture(t), "test")
	loc, err := readLocation(b.root, "/outer.zip")
	if err != nil {
		t.Fatal(err)
	}
	b.results <- result{loc: loc, history: -1}
	b.receive()
	b.results <- result{err: fs.ErrNotExist, history: -1}
	b.receive()
	if b.loc.path != "/outer.zip" || len(b.history) != 1 || b.historyIndex != 0 {
		t.Fatal("failed navigation changed location")
	}
	b.focusField(2)
	b.insert("INNER")
	if len(b.visible) != 1 {
		t.Fatal("filter failed")
	}
	b.focusField(1)
	b.insert("/outer.zip/inner.zip")
	if b.address != "/outer.zip/inner.zip" {
		t.Fatal(b.address)
	}
}
