package repo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPagedHistoryAndIncrementalManifests(t *testing.T) {
	name := filepath.Join(t.TempDir(), "paged.scs")
	r, e := createTestOptimized(name)
	must(t, e)
	var ids []GitOID
	for i := 0; i < 2300; i++ {
		b := []byte(fmt.Sprintf("historical body %08d", i))
		id, _, e := r.IngestGitBody(context.Background(), GitBlob, b, GitOID{}, nil, uint64(len(b)))
		must(t, e)
		ids = append(ids, id)
	}
	w := r.Empty()
	must(t, w.Mkdir("dir"))
	must(t, w.WriteFile("dir/file", []byte("original")))
	_, e = w.Publish("main")
	must(t, e)
	must(t, r.Checkpoint())
	base := r.fast.manifest.Runs[0].Ref
	before := r.gitStats
	must(t, r.Close())
	for pass := 0; pass < 20; pass++ {
		r, e = openTest(name)
		must(t, e)
		if r.fast == nil || len(r.objects) != 0 {
			t.Fatal("not a paged open")
		}
		w, e = r.Checkout("main")
		must(t, e)
		if !w.s.root.lazy {
			t.Fatal("eager workspace checkout")
		}
		must(t, w.WriteFile("dir/file", []byte(fmt.Sprintf("edit %d", pass))))
		_, e = w.Publish("main")
		must(t, e)
		found := false
		for _, run := range r.fast.manifest.Runs {
			found = found || run.Ref == base
		}
		if !found {
			t.Fatal("rewrote immutable history index")
		}
		if len(r.fast.manifest.Runs) > 10 {
			t.Fatal("small runs not compacted")
		}
		if r.gitStats.Objects != before.Objects || r.gitStats.Bytes != before.Bytes {
			t.Fatal("history statistics changed")
		}
		for _, i := range []int{0, 1023, 1024, 2299} {
			_, b, e := r.ReadGitObject(ids[i])
			must(t, e)
			if string(b) != fmt.Sprintf("historical body %08d", i) {
				t.Fatal("changed history")
			}
		}
		must(t, r.Close())
	}
	r, e = openTest(name)
	must(t, e)
	if len(r.GitObjectIDs()) != len(ids) {
		t.Fatal("lost identities")
	}
	s, e := r.StorageStats()
	must(t, e)
	must(t, r.Close())
	r, e = openTestVerified(name)
	must(t, e)
	s2, e := r.StorageStats()
	must(t, e)
	if s != s2 {
		t.Fatalf("index stats differ from scan: %+v vs %+v", s, s2)
	}
	w, e = r.Checkout("main")
	must(t, e)
	readEquals(t, w, "dir/file", []byte("edit 19"))
	must(t, r.Close())
}

func TestLazyWorkspaceIsolationAndMutations(t *testing.T) {
	name := filepath.Join(t.TempDir(), "lazy.scs")
	r, e := createTestOptimized(name)
	must(t, e)
	w := r.Empty()
	for _, d := range []string{"a", "b", "a/deep"} {
		must(t, w.Mkdir(d))
	}
	for i := 0; i < 100; i++ {
		must(t, w.WriteFile(fmt.Sprintf("b/f%03d", i), []byte("untouched")))
	}
	must(t, w.WriteFile("a/deep/f", []byte("original")))
	_, e = w.Publish("main")
	must(t, e)
	must(t, r.Checkpoint())
	must(t, r.Close())
	r, e = openTest(name)
	must(t, e)
	defer r.Close()
	w, e = r.Checkout("main")
	must(t, e)
	f, e := w.Fork()
	must(t, e)
	g, e := w.Fork()
	must(t, e)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, view := range []*Workspace{f, g} {
		wg.Add(1)
		go func(v *Workspace) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if _, e := v.ReadFile("a/deep/f"); e != nil {
					errs <- e
					return
				}
			}
		}(view)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		must(t, e)
	}
	must(t, f.WriteFile("a/deep/f", []byte("edited")))
	readEquals(t, g, "a/deep/f", []byte("original"))
	readEquals(t, w, "a/deep/f", []byte("original"))
	if n := findNode(f.s.root, "b"); n == nil || !n.lazy {
		t.Fatal("loaded unrelated directory")
	}
	must(t, f.Rename("a", "renamed"))
	must(t, f.Chmod("renamed/deep/f", 0755))
	must(t, f.Delete("renamed/deep/f"))
	must(t, f.Delete("renamed/deep"))
	must(t, f.Mkdir("renamed/new"))
	must(t, f.WriteFile("renamed/new/added", []byte("new")))
	_, e = f.Publish("edit")
	must(t, e)
	paths, e := f.PathsWithError()
	must(t, e)
	if len(paths) != 104 {
		t.Fatal(len(paths))
	}
	must(t, r.Close())
	r, e = openTest(name)
	must(t, e)
	defer r.Close()
	f, e = r.Checkout("edit")
	must(t, e)
	readEquals(t, f, "renamed/new/added", []byte("new"))
	w, e = r.Checkout("main")
	must(t, e)
	readEquals(t, w, "a/deep/f", []byte("original"))
}

func TestPagedPublicationTornTail(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "base")
	r, e := createTestOptimized(name)
	must(t, e)
	w := r.Empty()
	must(t, w.WriteFile("f", []byte("old")))
	_, e = w.Publish("main")
	must(t, e)
	must(t, r.Checkpoint())
	must(t, r.Close())
	before, e := os.ReadFile(name)
	must(t, e)
	r, e = openTest(name)
	must(t, e)
	w, e = r.Checkout("main")
	must(t, e)
	must(t, w.WriteFile("f", []byte("new")))
	_, e = w.Publish("main")
	must(t, e)
	must(t, r.Close())
	after, e := os.ReadFile(name)
	must(t, e)
	// Every truncation point of an incremental publication, including both
	// index manifests, must expose a complete old or complete new workspace.
	for cut := len(before); cut <= len(after); cut++ {
		p := filepath.Join(dir, "cut")
		must(t, os.WriteFile(p, after[:cut], 0600))
		probe, e := openTest(p)
		must(t, e)
		view, e := probe.Checkout("main")
		must(t, e)
		b, e := view.ReadFile("f")
		must(t, e)
		if !bytes.Equal(b, []byte("old")) && !bytes.Equal(b, []byte("new")) {
			t.Fatalf("partial publication at %d: %q", cut, b)
		}
		must(t, probe.Close())
	}
}

func TestDeferredDescriptorCorruption(t *testing.T) {
	name := filepath.Join(t.TempDir(), "bad")
	r, e := createTestOptimized(name)
	must(t, e)
	w := r.Empty()
	must(t, w.WriteFile("f", []byte("content")))
	_, e = w.Publish("main")
	must(t, e)
	n := findNode(w.s.root, "f")
	loc, ok := r.lookupObject(key(n.id))
	if !ok {
		t.Fatal("missing descriptor")
	}
	must(t, r.Checkpoint())
	must(t, r.Close())
	f, e := os.OpenFile(name, os.O_RDWR, 0)
	must(t, e)
	_, e = f.WriteAt([]byte{'!'}, loc.offset)
	must(t, e)
	must(t, f.Close())
	r, e = openTest(name)
	must(t, e)
	defer r.Close()
	w, e = r.Checkout("main")
	must(t, e)
	if _, e = w.Stat("f"); e == nil {
		t.Fatal("accepted descriptor corruption")
	}
	if _, e = w.PathsWithError(); e == nil {
		t.Fatal("enumeration hid corruption")
	}
	if _, e = w.Publish("bad"); e == nil {
		t.Fatal("published failed lazy load")
	}
	if e = r.Scrub(false); e == nil {
		t.Fatal("physical scrub missed corruption")
	}
}

func TestPagedMigrationAndIncrementalGitNamespaces(t *testing.T) {
	name := filepath.Join(t.TempDir(), "migration")
	r, e := createTestOptimized(name)
	must(t, e)
	b := []byte("shared canonical blob")
	sha1, _, e := r.IngestGitBody(context.Background(), GitBlob, b, GitOID{}, nil, uint64(len(b)))
	must(t, e)
	must(t, r.legacyCheckpoint())
	must(t, r.Close())
	r, e = openTest(name)
	must(t, e)
	if r.fast != nil {
		t.Fatal("legacy checkpoint unexpectedly paged")
	}
	must(t, r.Checkpoint())
	must(t, r.Close())
	r, e = openTest(name)
	must(t, e)
	h := sha256.New()
	fmt.Fprintf(h, "blob %d%c", len(b), 0)
	h.Write(b)
	sha2, e := GitOIDFromBytes(h.Sum(nil))
	must(t, e)
	_, e = r.PutGitObject(context.Background(), sha2, GitBlob, int64(len(b)), bytes.NewReader(b))
	must(t, e)
	must(t, r.Close()) // Close must seal an unpublished Git insertion, too.
	r, e = openTest(name)
	must(t, e)
	defer r.Close()
	for _, id := range []GitOID{sha1, sha2} {
		_, got, e := r.ReadGitObject(id)
		must(t, e)
		if !bytes.Equal(got, b) {
			t.Fatal("namespace lost")
		}
		must(t, r.VerifyGitObject(id))
	}
	if r.GitStatistics().Objects != 2 || len(r.GitObjectIDs()) != 2 {
		t.Fatal("incorrect Git counts")
	}
	before, e := os.Stat(name)
	must(t, e)
	must(t, r.Checkpoint())
	after, e := os.Stat(name)
	must(t, e)
	if before.Size() != after.Size() {
		t.Fatal("no-op checkpoint appended data")
	}
}

func TestDeferredPersistentPageCorruption(t *testing.T) {
	name := filepath.Join(t.TempDir(), "page")
	r, e := createTestOptimized(name)
	must(t, e)
	var oid GitOID
	for i := 0; i < 1100; i++ {
		b := []byte(fmt.Sprintf("blob %d", i))
		oid, _, e = r.IngestGitBody(context.Background(), GitBlob, b, GitOID{}, nil, uint64(len(b)))
		must(t, e)
	}
	must(t, r.Checkpoint())
	run, e := r.fastRun(r.fast.manifest.Runs[0].Ref)
	must(t, e)
	// Find the secondary page which contains our target. Opening a repository
	// without workspaces must not touch these history-only pages.
	page := run.GitPages[0]
	for _, p := range run.GitPages {
		if bytes.Compare(p.First[:], oid[:]) <= 0 {
			page = p
		}
	}
	must(t, r.Close())
	f, e := os.OpenFile(name, os.O_RDWR, 0)
	must(t, e)
	var b [1]byte
	_, e = f.ReadAt(b[:], page.Ref.Offset)
	must(t, e)
	b[0] ^= 1
	_, e = f.WriteAt(b[:], page.Ref.Offset)
	must(t, e)
	must(t, f.Close())
	r, e = openTest(name)
	must(t, e)
	defer r.Close()
	if _, _, e = r.ReadGitObject(oid); e == nil {
		t.Fatal("accepted corrupt index page")
	}
	if e = r.Checkpoint(); e == nil {
		t.Fatal("failed lookup did not poison writes")
	}
	if e = r.Scrub(false); e == nil {
		t.Fatal("scrub missed corrupt index page")
	}
}
