package repo

import (
	"context"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestGraphQueriesAgainstDAGOracle(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(16 << 20))
	must(t, e)
	defer r.Close()
	rng := rand.New(rand.NewSource(17))
	ids := []ID{}
	ancestors := []map[ID]bool{}
	for i := 0; i < 60; i++ {
		meta := RevisionMetadata{Message: fmt.Sprint(i)}
		closure := map[ID]bool{}
		if i > 0 {
			p := rng.Intn(i)
			meta.Parents = append(meta.Parents, ids[p])
			for id := range ancestors[p] {
				closure[id] = true
			}
			q := rng.Intn(i)
			if q != p {
				meta.Parents = append(meta.Parents, ids[q])
				for id := range ancestors[q] {
					closure[id] = true
				}
			}
		}
		id, e := r.Empty().Revision(meta)
		must(t, e)
		closure[id] = true
		ids = append(ids, id)
		ancestors = append(ancestors, closure)
	}
	for n := 0; n < 100; n++ {
		a, b := rng.Intn(len(ids)), rng.Intn(len(ids))
		yes, e := r.IsAncestor(context.Background(), ids[a], ids[b], GraphLimits{})
		must(t, e)
		if yes != ancestors[b][ids[a]] {
			t.Fatal("ancestry differs from oracle")
		}
		common := []ID{}
		for id := range ancestors[a] {
			if ancestors[b][id] {
				common = append(common, id)
			}
		}
		want := []ID{}
		for _, id := range common {
			best := true
			for _, other := range common {
				if other == id {
					continue
				}
				for i, oid := range ids {
					if oid == other && ancestors[i][id] {
						best = false
					}
				}
			}
			if best {
				want = append(want, id)
			}
		}
		sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
		got, e := r.MergeBases(context.Background(), ids[a], ids[b], GraphLimits{})
		must(t, e)
		if !reflect.DeepEqual(got, want) {
			t.Fatal(got, want)
		}
	}
}
func TestIndexedCatalogRejectsForgedTransition(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(4 << 20))
	must(t, e)
	defer r.Close()
	a, e := r.Empty().Revision(RevisionMetadata{Message: "a"})
	must(t, e)
	b, e := r.Empty().Revision(RevisionMetadata{Message: "b"})
	must(t, e)
	must(t, r.EnableIndexedRefs())
	must(t, r.Promote("main", "", a))
	old := r.refIndex.id
	e = r.installCatalog(catalog{Indexed: true, Index: old, Update: &refUpdate{Name: "main", Expected: a, Next: b}})
	if e == nil || r.refs["main"] != a {
		t.Fatal("forged transition changed root", e)
	}
}
func FuzzGlobStateMatchesOracle(f *testing.F) {
	for _, seed := range [][2]string{{"**/a", "x/a"}, {"a/**", "a"}, {"[ab]/*", "a/f"}, {"**/**/z", "a/b/z"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, pattern, name string) {
		if len(pattern) > 128 || len(name) > 128 {
			return
		}
		p, e := clean(pattern)
		if e != nil || pattern == "" {
			return
		}
		n, e := clean(name)
		if e != nil || n == "." {
			return
		}
		want, e := Match(pattern, n)
		if e != nil {
			return
		}
		got, descend := globState(strings.Split(p, "/"), strings.Split(n, "/"))
		if got != want {
			t.Fatal(pattern, n, got, want)
		}
		extension, e := Match(pattern, n+"/a")
		if e == nil && extension && !descend {
			t.Fatal("pruned a matching descendant")
		}
	})
}
