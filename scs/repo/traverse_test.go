package repo

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/tinyrange/trex/storage"
)

func TestGlobPagesMatchOracle(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(8 << 20))
	must(t, e)
	defer r.Close()
	w := r.Empty()
	for _, p := range []string{"a", "a/sub", "b", "b/sub", ".hidden"} {
		must(t, w.Mkdir(p))
	}
	for _, p := range []string{"a.z", "a/file.go", "a/sub/x.go", "a/sub/z.txt", "b/file.go", "b/sub/x.go", ".hidden/a.go", "a/sub/a"} {
		must(t, w.WriteFile(p, []byte(p)))
	}
	must(t, w.Symlink("link", "a"))
	all, e := w.PathsWithError()
	must(t, e)
	for _, pattern := range []string{"**", "a/**", "**/*.go", "*/sub/*", "**/sub/**", "a", "a*", "[ab]/**/x.go", ".hidden/*", "missing/**", "**/**/a"} {
		t.Run(pattern, func(t *testing.T) {
			want := []string{}
			for _, p := range all {
				yes, e := Match(pattern, p)
				must(t, e)
				if yes {
					want = append(want, p)
				}
			}
			sort.Strings(want)
			got := []string{}
			after := ""
			view := w.View()
			for {
				page, e := view.GlobPage(context.Background(), pattern, after, QueryLimits{Limit: 2})
				must(t, e)
				got = append(got, page.Paths...)
				if page.Next == "" {
					break
				}
				if page.Next <= after {
					t.Fatal("cursor did not progress")
				}
				after = page.Next
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %v want %v", got, want)
			}
			compatibility, e := w.Glob(pattern)
			must(t, e)
			if !reflect.DeepEqual(compatibility, want) {
				t.Fatal(compatibility, want)
			}
		})
	}
	if _, e = w.GlobPage(context.Background(), "**", "", QueryLimits{Limit: 1, MaxVisited: 1}); !errors.Is(e, ErrQueryLimit) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = w.GlobPage(ctx, "**", "", QueryLimits{Limit: 1}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	pinned := w.View()
	must(t, w.WriteFile("new", []byte("new")))
	got, e := pinned.Glob("new")
	must(t, e)
	if len(got) != 0 {
		t.Fatal("view was not pinned")
	}
}
func TestNarrowGlobSkipsDeferredInvalidTree(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(4 << 20))
	must(t, e)
	defer r.Close()
	blob := putLazyFixture(t, r, GitBlob, []byte("content"))
	good := putLazyFixture(t, r, GitTree, gitTreeFixture("100644", "file", blob))
	bad := putLazyFixture(t, r, GitTree, []byte("invalid tree"))
	root := putLazyFixture(t, r, GitTree, append(gitTreeFixture("40000", "good", good), gitTreeFixture("40000", "unrelated", bad)...))
	must(t, r.PublishGit(GitCatalog{Name: "fixture", Head: root.String(), Refs: map[string]string{"refs/heads/main": root.String()}}))
	w, e := r.CheckoutGit(context.Background(), "fixture", root.String())
	must(t, e)
	page, e := w.GlobPage(context.Background(), "good/**", "", QueryLimits{Limit: 10})
	must(t, e)
	if !reflect.DeepEqual(page.Paths, []string{"good", "good/file"}) {
		t.Fatal(page)
	}
	if _, e = w.Glob("**"); e == nil {
		t.Fatal("broad traversal missed invalid subtree")
	}
}
func TestNarrowDiffSkipsUnrelatedPayloads(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(8 << 20))
	must(t, e)
	defer r.Close()
	before := r.Empty()
	must(t, before.Mkdir("wanted"))
	must(t, before.Mkdir("other"))
	must(t, before.WriteFile("wanted/f", []byte("old")))
	must(t, before.WriteFile("other/f", []byte("old")))
	after, e := before.Fork()
	must(t, e)
	must(t, after.WriteFile("wanted/f", []byte("new")))
	must(t, after.WriteFile("other/f", []byte("other")))
	got, e := DiffLimited(context.Background(), before, after, DiffOptions{Prefix: "wanted", MaxChanges: 10, MaxVisited: 100})
	must(t, e)
	if len(got) != 1 || got[0].Path != "wanted/f" {
		t.Fatal(got)
	}
	if _, e = DiffLimited(context.Background(), before, after, DiffOptions{Prefix: ".", MaxChanges: 1, MaxVisited: 100}); !errors.Is(e, ErrQueryLimit) {
		t.Fatal(e)
	}
	if _, e = DiffLimited(context.Background(), before, after, DiffOptions{Prefix: "wanted", MaxChanges: 10, MaxVisited: 1}); !errors.Is(e, ErrQueryLimit) {
		t.Fatal(e)
	}
}
func TestOneEditMetadataScaling(t *testing.T) {
	for _, count := range []int{100, 10000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			r, e := CreateOptimized(storage.NewMemoryStore(32 << 20))
			must(t, e)
			defer r.Close()
			w := r.Empty()
			must(t, w.Mkdir("files"))
			for i := 0; i < count; i++ {
				must(t, w.WriteFile(fmt.Sprintf("files/%06d", i), []byte("initial")))
			}
			_, e = w.Snapshot()
			must(t, e)
			before := r.OperationStats()
			f, e := w.Fork()
			must(t, e)
			must(t, f.WriteFile("files/000000", []byte("changed")))
			_, e = f.Snapshot()
			must(t, e)
			after := r.OperationStats()
			records := after.RecordsAppended - before.RecordsAppended
			if records > 32 {
				t.Fatalf("one edit appended %d records across %d files", records, count)
			}
			t.Logf("%d files: one edit appended %d records / %d bytes", count, records, after.BytesAppended-before.BytesAppended)
		})
	}
}
