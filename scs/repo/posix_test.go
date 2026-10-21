package repo

import (
	"errors"
	"io/fs"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRenameReplaceAtomicAndIsolated(t *testing.T) {
	r, err := createTestOptimized(filepath.Join(t.TempDir(), "r.scs"))
	must(t, err)
	defer r.Close()
	w := r.Empty()
	must(t, w.Mkdir("src"))
	must(t, w.WriteFile("src/file", []byte("source")))
	must(t, w.Mkdir("dst"))
	must(t, w.WriteFile("dst/keep", []byte("target")))
	fork, err := w.Fork()
	must(t, err)
	if err = w.RenameReplace("src", "dst", false); !errors.Is(err, syscall.ENOTEMPTY) {
		t.Fatalf("got %v", err)
	}
	b, err := w.ReadFile("src/file")
	must(t, err)
	if string(b) != "source" {
		t.Fatal(string(b))
	}
	if err = w.RenameReplace("src/file", "dst", false); !errors.Is(err, syscall.EISDIR) {
		t.Fatalf("got %v", err)
	}
	if err = w.RenameReplace("src/file", "dst/keep", true); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("got %v", err)
	}
	reader, err := w.OpenReader("dst/keep")
	must(t, err)
	defer reader.Close()
	must(t, w.RenameReplace("src/file", "dst/keep", false))
	b, err = w.ReadFile("dst/keep")
	must(t, err)
	if string(b) != "source" {
		t.Fatal(string(b))
	}
	old := make([]byte, 6)
	_, err = reader.ReadAt(old, 0)
	must(t, err)
	if string(old) != "target" {
		t.Fatal(string(old))
	}
	b, err = fork.ReadFile("dst/keep")
	must(t, err)
	if string(b) != "target" {
		t.Fatal("fork changed")
	}
	if _, err = w.Stat("src/file"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
}

func TestTimesEagerLazyAndVerified(t *testing.T) {
	for _, optimized := range []bool{false, true} {
		t.Run(map[bool]string{false: "v2", true: "v3"}[optimized], func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "r.scs")
			var r *Repository
			var err error
			if optimized {
				r, err = createTestOptimized(p)
			} else {
				r, err = createTest(p)
			}
			must(t, err)
			w := r.Empty()
			must(t, w.Mkdir("d"))
			must(t, w.WriteFile("d/f", []byte("bytes")))
			must(t, w.Symlink("s", "d/f"))
			times := Times{A: 1234567890, M: 3456789012, C: 4567890123}
			for _, p := range []string{".", "d", "d/f", "s"} {
				must(t, w.SetTimes(p, times))
			}
			_, err = w.Publish("main")
			must(t, err)
			if optimized {
				must(t, r.Checkpoint())
			}
			must(t, r.Close())
			for _, verified := range []bool{false, true} {
				if verified {
					r, err = openTestVerified(p)
				} else {
					r, err = openTest(p)
				}
				must(t, err)
				w, err = r.Checkout("main")
				must(t, err)
				for _, p := range []string{".", "d", "d/f", "s"} {
					e, err := w.Stat(p)
					must(t, err)
					if e.Times != times {
						t.Fatalf("%s: %+v", p, e.Times)
					}
				}
				must(t, r.Close())
			}
		})
	}
}
