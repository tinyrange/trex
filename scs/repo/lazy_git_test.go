package repo

import (
	"context"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"testing"
)

func putLazyFixture(t *testing.T, r *Repository, kind byte, data []byte) GitOID {
	t.Helper()
	id, _, e := r.IngestGitBody(context.Background(), kind, data, GitOID{}, nil, uint64(len(data)))
	must(t, e)
	return id
}
func gitTreeFixture(mode, name string, id GitOID) []byte {
	b := []byte(mode + " " + name + "\x00")
	return append(b, id[:int(id[32])]...)
}
func TestLazyGitTreeAccessAndPublication(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(4 << 20))
	must(t, e)
	defer r.Close()
	blob := putLazyFixture(t, r, GitBlob, []byte("content"))
	sub := putLazyFixture(t, r, GitTree, gitTreeFixture("100644", "file", blob))
	// A separately valid object whose tree syntax is invalid. It must only fail
	// when traversed, and must prevent a supposedly complete publication.
	bad := putLazyFixture(t, r, GitTree, []byte("invalid tree"))
	rootData := append(gitTreeFixture("40000", "good", sub), gitTreeFixture("40000", "unrelated", bad)...)
	root := putLazyFixture(t, r, GitTree, rootData)
	commit := putLazyFixture(t, r, GitCommit, []byte(fmt.Sprintf("tree %s\nauthor A <a@b> 0 +0000\ncommitter A <a@b> 0 +0000\n\nfixture\n", root.String())))
	must(t, r.PublishGit(GitCatalog{Name: "fixture", Head: commit.String(), Refs: map[string]string{"refs/heads/main": commit.String()}}))
	w, e := r.CheckoutGit(context.Background(), "fixture", "HEAD")
	must(t, e)
	if !w.s.root.lazy {
		t.Fatal("checkout eagerly materialized tree")
	}
	tree, e := w.SnapshotTree()
	must(t, e)
	names, e := tree.ReadDir(".")
	must(t, e)
	if len(names) != 2 {
		t.Fatal(names)
	}
	if n := findNode(tree.(*projectTree).w.s.root, "unrelated"); n == nil || !n.lazy {
		t.Fatal("listing materialized unrelated child")
	}
	file, e := tree.OpenFile("good/file")
	must(t, e)
	b := make([]byte, 7)
	_, e = file.ReadAt(b, 0)
	must(t, e)
	if string(b) != "content" {
		t.Fatal(string(b))
	}
	if _, e = w.Publish("incomplete"); e == nil {
		t.Fatal("published deferred invalid tree")
	}
	if _, ok := r.Refs()["incomplete"]; ok {
		t.Fatal("failed publication installed ref")
	}
	validRoot := putLazyFixture(t, r, GitTree, gitTreeFixture("40000", "good", sub))
	w, e = r.CheckoutGit(context.Background(), "fixture", validRoot.String())
	must(t, e)
	_, e = w.Publish("main")
	must(t, e)
	must(t, r.Checkpoint())
	artifact, e := r.SnapshotFile()
	must(t, e)
	store := storage.NewMemoryStore(4 << 20)
	buf := make([]byte, artifact.Size())
	_, e = artifact.ReadAt(buf, 0)
	must(t, e)
	_, e = store.WriteAt(buf, 0)
	must(t, e)
	reopened, e := Open(store)
	must(t, e)
	defer reopened.Close()
	saved, e := reopened.Checkout("main")
	must(t, e)
	got, e := saved.ReadFile("good/file")
	must(t, e)
	if string(got) != "content" {
		t.Fatal(string(got))
	}
}
