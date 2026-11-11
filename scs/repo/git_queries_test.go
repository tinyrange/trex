package repo

import (
	"context"
	"errors"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"reflect"
	"sort"
	"testing"
)

func TestGitGraphQueries(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(8 << 20))
	must(t, e)
	defer r.Close()
	tree := putLazyFixture(t, r, GitTree, nil)
	commit := func(message string, parents ...GitOID) GitOID {
		text := fmt.Sprintf("tree %s\n", tree.String())
		for _, p := range parents {
			text += fmt.Sprintf("parent %s\n", p.String())
		}
		text += "author A <a@b> 0 +0000\ncommitter A <a@b> 0 +0000\n\n" + message + "\n"
		return putLazyFixture(t, r, GitCommit, []byte(text))
	}
	root := commit("root")
	left := commit("left", root)
	right := commit("right", root)
	a := commit("a", left, right)
	b := commit("b", right, left)
	bases, e := r.GitMergeBases(context.Background(), a, b, GraphLimits{})
	must(t, e)
	want := []GitOID{left, right}
	sort.Slice(want, func(i, j int) bool { return want[i].String() < want[j].String() })
	if !reflect.DeepEqual(bases, want) {
		t.Fatal(bases, want)
	}
	yes, e := r.GitIsAncestor(context.Background(), root, a, GraphLimits{})
	must(t, e)
	if !yes {
		t.Fatal("lost ancestor")
	}
	yes, e = r.GitIsAncestor(context.Background(), a, b, GraphLimits{})
	must(t, e)
	if yes {
		t.Fatal("siblings are ancestors")
	}
	if _, e = r.GitMergeBases(context.Background(), a, b, GraphLimits{MaxVisited: 1}); !errors.Is(e, ErrQueryLimit) {
		t.Fatal(e)
	}
	if _, e = r.GitIsAncestor(context.Background(), tree, a, GraphLimits{}); e == nil {
		t.Fatal("tree accepted as a commit")
	}
}
