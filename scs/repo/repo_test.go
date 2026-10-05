package repo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func newRepo(t *testing.T) (*Repository, string) {
	t.Helper()
	name := filepath.Join(t.TempDir(), "test.scs")
	r, err := createTest(name)
	must(t, err)
	t.Cleanup(func() { r.Close() })
	return r, name
}
func readEquals(t *testing.T, w *Workspace, p string, want []byte) {
	t.Helper()
	got, err := w.ReadFile(p)
	must(t, err)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: got %q, want %q", p, got, want)
	}
}

func TestPersistenceSharingAndForkIsolation(t *testing.T) {
	r, name := newRepo(t)
	w := r.Empty()
	must(t, w.Mkdir("src"))
	must(t, w.Mkdir("empty"))
	content := append(bytes.Repeat([]byte("a"), BlockSize), bytes.Repeat([]byte("b"), BlockSize)...)
	content = append(content, 0, 255, 1)
	must(t, w.WriteFile("src/data", content))
	must(t, w.WriteFile("copy", content))
	must(t, w.Chmod("copy", 0755))
	must(t, w.Symlink("link", "src/data"))
	id, err := w.Publish("main")
	must(t, err)
	// Identical blocks are stored once, even across two logical files.
	blocks := 0
	for _, loc := range r.objects {
		if loc.kind == blockKind {
			blocks++
		}
	}
	if blocks != 4 {
		t.Fatalf("got %d distinct blocks, want 3 data + 1 symlink", blocks)
	}
	a, err := r.Fork(id)
	must(t, err)
	b, err := r.Fork(id)
	must(t, err)
	changed := bytes.Clone(content)
	changed[BlockSize+2] = 'X'
	must(t, a.WriteFile("src/data", changed))
	ae, _ := a.Stat("src/data")
	be, _ := b.Stat("src/data")
	if ae.Blocks[0] != be.Blocks[0] || ae.Blocks[1] == be.Blocks[1] || ae.Blocks[2] != be.Blocks[2] {
		t.Fatal("unchanged blocks were not shared")
	}
	must(t, b.WriteFile("src/data", []byte("agent b")))
	must(t, a.Rename("src", "lib"))
	_, err = a.Publish("agent-a")
	must(t, err)
	_, err = b.Publish("agent-b")
	must(t, err)
	readEquals(t, w, "src/data", content)
	must(t, r.Close())
	r, err = openTest(name)
	must(t, err)
	defer r.Close()
	main, err := r.Checkout("main")
	must(t, err)
	readEquals(t, main, "src/data", content)
	aa, err := r.Checkout("agent-a")
	must(t, err)
	readEquals(t, aa, "lib/data", changed)
	bb, err := r.Checkout("agent-b")
	must(t, err)
	readEquals(t, bb, "src/data", []byte("agent b"))
	e, err := aa.Stat("copy")
	must(t, err)
	if e.Mode != 0755 {
		t.Fatal("lost executable mode")
	}
	target, err := aa.Readlink("link")
	must(t, err)
	if target != "src/data" {
		t.Fatal(target)
	}
	names, err := main.ListDir("empty")
	must(t, err)
	if len(names) != 0 {
		t.Fatal(names)
	}
	// Snapshots do not depend on insertion order and can be reopened by ID.
	same, err := main.Snapshot()
	must(t, err)
	if same != id {
		t.Fatalf("unstable snapshot ID: %s != %s", same, id)
	}
}

func TestCapabilitiesAndAtomicMutations(t *testing.T) {
	r, _ := newRepo(t)
	w := r.Empty()
	must(t, w.Mkdir("d"))
	must(t, w.WriteFile("d/f", []byte("one one")))
	ro := w.Readonly()
	for _, operation := range []func() error{
		func() error { return ro.WriteFile("d/f", nil) }, func() error { return ro.Mkdir("x") }, func() error { return ro.Delete("d/f") },
		func() error { return ro.Rename("d", "e") }, func() error { return ro.Replace("d/f", "one", "two") }, func() error { return ro.Chmod("d/f", 0) },
		func() error { _, e := ro.Snapshot(); return e }, func() error { _, e := ro.Publish("x"); return e }, func() error { _, e := ro.Fork(); return e }, func() error { return ro.Symlink("l", "d/f") },
	} {
		if err := operation(); !errors.Is(err, ErrReadOnly) {
			t.Fatalf("readonly operation: %v", err)
		}
	}
	must(t, w.Replace("d/f", "one", "two"))
	readEquals(t, ro, "d/f", []byte("two two"))
	for _, p := range []string{"../escape", "d/../../escape", "/absolute", "bad\x00name", "bad\\name"} {
		if err := w.WriteFile(p, nil); err == nil {
			t.Fatalf("accepted %q", p)
		}
	}
	must(t, w.Symlink("outside", "/etc/passwd"))
	if _, err := w.ReadFile("outside"); err == nil {
		t.Fatal("followed symlink")
	}
	if err := w.WriteFile("outside", nil); err == nil {
		t.Fatal("overwrote symlink")
	}
	if err := w.WriteFile("outside/child", nil); err == nil {
		t.Fatal("traversed symlink")
	}
	if err := w.Rename("d", "d/sub"); err == nil {
		t.Fatal("moved into itself")
	}
	if err := w.Delete("d"); err == nil {
		t.Fatal("removed nonempty directory")
	}
	if err := w.Replace("d/f", "missing", "oops"); err == nil {
		t.Fatal("missing replacement succeeded")
	}
	if err := w.WriteFrom("d/f", &brokenReader{}); err == nil {
		t.Fatal("failed input accepted")
	}
	readEquals(t, w, "d/f", []byte("two two"))
	must(t, w.WriteFile("existing", nil))
	if err := w.Rename("d/f", "existing"); err == nil {
		t.Fatal("rename overwrote destination")
	}
	must(t, w.Rename("d", "e"))
	readEquals(t, w, "e/f", []byte("two two"))
}

type brokenReader struct{ once bool }

func (b *brokenReader) Read(p []byte) (int, error) {
	if !b.once {
		b.once = true
		return copy(p, bytes.Repeat([]byte("z"), BlockSize)), nil
	}
	return 0, errors.New("input failed")
}

func TestConcurrentPublicationAndLocking(t *testing.T) {
	r, name := newRepo(t)
	w := r.Empty()
	must(t, w.WriteFile("f", []byte("base")))
	_, err := w.Publish("main")
	must(t, err)
	if other, err := openTest(name); err == nil {
		other.Close()
		t.Fatal("second repository handle acquired lock")
	}
	const workers = 8
	workspaces := make([]*Workspace, workers)
	for i := range workspaces {
		workspaces[i], err = r.Checkout("main")
		must(t, err)
		must(t, workspaces[i].WriteFile("f", []byte(fmt.Sprint(i))))
	}
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for _, w := range workspaces {
		wg.Add(1)
		go func(w *Workspace) { defer wg.Done(); _, err := w.Publish("main"); results <- err }(w)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatalf("%d concurrent publishers succeeded", success)
	}
}

func TestRecoveryAtEveryPublicationByte(t *testing.T) {
	r, name := newRepo(t)
	w := r.Empty()
	must(t, w.WriteFile("f", []byte("before")))
	old, err := w.Publish("main")
	must(t, err)
	st, err := os.Stat(name)
	must(t, err)
	boundary := int(st.Size())
	must(t, w.WriteFile("f", []byte("after")))
	latest, err := w.Publish("main")
	must(t, err)
	must(t, r.Close())
	full, err := os.ReadFile(name)
	must(t, err)
	// Every truncation of the append sequence must expose the old root; only the
	// complete final publication exposes the new root. Subsequent writes must work.
	candidate := filepath.Join(t.TempDir(), "crash.scs")
	for cut := boundary; cut <= len(full); cut++ {
		must(t, os.WriteFile(candidate, full[:cut], 0600))
		recovered, err := openTest(candidate)
		if err != nil {
			t.Fatalf("cut %d: %v", cut-boundary, err)
		}
		expected := old
		if cut == len(full) {
			expected = latest
		}
		if got := recovered.Refs()["main"]; got != expected {
			t.Fatalf("cut %d: %s != %s", cut-boundary, got, expected)
		}
		view, err := recovered.Checkout("main")
		must(t, err)
		want := "before"
		if cut == len(full) {
			want = "after"
		}
		readEquals(t, view, "f", []byte(want))
		must(t, view.WriteFile("f", []byte("recovered")))
		_, err = view.Publish("main")
		must(t, err)
		must(t, recovered.Close())
	}
}
func TestUnpublishedEditsAndCorruption(t *testing.T) {
	r, name := newRepo(t)
	w := r.Empty()
	must(t, w.WriteFile("f", []byte("published")))
	id, err := w.Publish("main")
	must(t, err)
	must(t, w.WriteFile("f", []byte("not published")))
	snap, err := w.Snapshot()
	must(t, err)
	must(t, r.Close())
	r, err = openTest(name)
	must(t, err)
	if r.Refs()["main"] != id {
		t.Fatal("snapshot moved named root")
	}
	saved, err := r.Fork(snap)
	must(t, err)
	readEquals(t, saved, "f", []byte("not published"))
	must(t, r.Close())
	raw, err := os.ReadFile(name)
	must(t, err)
	raw[len(magic)+headerSize] ^= 1
	must(t, os.WriteFile(name, raw, 0600))
	if r, err = openTest(name); err == nil {
		r.Close()
		t.Fatal("checksum corruption silently accepted")
	}
}
func TestRecordBounds(t *testing.T) {
	r, name := newRepo(t)
	must(t, r.Close())
	var h [headerSize]byte
	h[0] = blockKind
	binary.BigEndian.PutUint64(h[1:9], ^uint64(0))
	f, err := os.OpenFile(name, os.O_APPEND|os.O_WRONLY, 0)
	must(t, err)
	_, err = f.Write(h[:])
	must(t, err)
	must(t, f.Close())
	if r, err = openTest(name); err == nil {
		r.Close()
		t.Fatal("oversized record accepted")
	}
}
func TestGlob(t *testing.T) {
	r, _ := newRepo(t)
	w := r.Empty()
	must(t, w.Mkdir("a"))
	must(t, w.Mkdir("a/b"))
	for _, p := range []string{"root.go", "a/one.go", "a/b/two.go", "a/no.txt", ".hidden.go"} {
		must(t, w.WriteFile(p, nil))
	}
	got, err := w.Glob("**/*.go")
	must(t, err)
	want := []string{".hidden.go", "a/b/two.go", "a/one.go", "root.go"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v != %v", got, want)
	}
	got, err = w.Glob("a/*.go")
	must(t, err)
	if strings.Join(got, ",") != "a/one.go" {
		t.Fatal(got)
	}
	if _, err = w.Glob("["); err == nil {
		t.Fatal("invalid glob accepted")
	}
}
func TestCreateNeverOverwrites(t *testing.T) {
	_, name := newRepo(t)
	before, err := os.ReadFile(name)
	must(t, err)
	if r, err := createTest(name); err == nil {
		r.Close()
		t.Fatal("overwrote existing repository")
	}
	after, err := os.ReadFile(name)
	must(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("existing bytes changed")
	}
}

var _ io.Reader = (*brokenReader)(nil)
