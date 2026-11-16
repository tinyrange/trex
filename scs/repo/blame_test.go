package repo

import (
	"context"
	"errors"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"testing"
)

func TestNativeAndGitFirstParentBlame(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(8 << 20))
	must(t, e)
	defer r.Close()
	w := r.Empty()
	must(t, w.WriteFile("f", []byte("a\nb\n")))
	root, e := w.Revision(RevisionMetadata{Message: "root"})
	must(t, e)
	must(t, w.WriteFile("f", []byte("a\ninserted\nb\n")))
	inserted, e := w.Revision(RevisionMetadata{Parents: []ID{root}, Message: "insert"})
	must(t, e)
	must(t, w.WriteFile("other", []byte("irrelevant")))
	unchanged, e := w.Revision(RevisionMetadata{Parents: []ID{inserted}, Message: "unchanged"})
	must(t, e)
	lines, e := r.Blame(context.Background(), unchanged, "f", BlameLimits{})
	must(t, e)
	if len(lines) != 3 || lines[0].Revision != string(root) || lines[1].Revision != string(inserted) || lines[2].Revision != string(root) || lines[2].SourceLine != 2 {
		t.Fatal(lines)
	}
	if _, e = r.Blame(context.Background(), unchanged, "f", BlameLimits{MaxCells: 1}); !errors.Is(e, ErrQueryLimit) {
		t.Fatal(e)
	}
	if _, e = r.Blame(context.Background(), unchanged, "f", BlameLimits{MaxFileBytes: 1}); !errors.Is(e, ErrQueryLimit) {
		t.Fatal(e)
	}
	if _, e = r.Blame(context.Background(), unchanged, "f", BlameLimits{MaxVisited: 1}); !errors.Is(e, ErrQueryLimit) {
		t.Fatal(e)
	}
	must(t, w.WriteFile("binary", []byte{0, 1}))
	binary, e := w.Revision(RevisionMetadata{})
	must(t, e)
	if _, e = r.Blame(context.Background(), binary, "binary", BlameLimits{}); e == nil {
		t.Fatal("binary blamed")
	}
	// Same attribution using imported Git objects, with explicit identity domains.
	gitCommit := func(data, message string, parents ...GitOID) GitOID {
		blob := putLazyFixture(t, r, GitBlob, []byte(data))
		tree := putLazyFixture(t, r, GitTree, gitTreeFixture("100644", "f", blob))
		text := fmt.Sprintf("tree %s\n", tree.String())
		for _, p := range parents {
			text += fmt.Sprintf("parent %s\n", p.String())
		}
		text += "author A <a@b> 0 +0000\ncommitter A <a@b> 0 +0000\n\n" + message + "\n"
		return putLazyFixture(t, r, GitCommit, []byte(text))
	}
	gitRoot := gitCommit("a\nb\n", "root")
	gitNext := gitCommit("a\ninserted\nb\n", "insert", gitRoot)
	must(t, r.PublishGit(GitCatalog{Name: "git", Head: gitNext.String(), Refs: map[string]string{"refs/heads/main": gitNext.String()}}))
	lines, e = r.GitBlame(context.Background(), "git", gitNext, "f", BlameLimits{})
	must(t, e)
	if len(lines) != 3 || lines[0].Revision != gitRoot.String() || lines[1].Revision != gitNext.String() || lines[2].SourceLine != 2 {
		t.Fatal(lines)
	}
}
func TestTargetImpactUsesExplicitPolicy(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(8 << 20))
	must(t, e)
	defer r.Close()
	before := r.Empty()
	must(t, before.Mkdir("src"))
	must(t, before.WriteFile("src/f.go", []byte("old")))
	after, e := before.Fork()
	must(t, e)
	must(t, after.WriteFile("src/f.go", []byte("new")))
	targets := []TargetSpec{{Name: "compile", Patterns: []string{"src/**/*.go"}}, {Name: "docs", Patterns: []string{"docs/**"}}}
	affected, e := AffectedTargets(context.Background(), before, after, targets, DiffOptions{Prefix: ".", MaxChanges: 100, MaxVisited: 1000})
	must(t, e)
	if len(affected) != 1 || affected[0] != "compile" {
		t.Fatal(affected)
	}
}
