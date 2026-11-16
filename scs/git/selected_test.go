package gitstore

import (
	"context"
	"path/filepath"
	"testing"

	scsnative "github.com/tinyrange/trex/scs/native"
	"github.com/tinyrange/trex/scs/repo"
)

func TestSelectedRefClone(t *testing.T) {
	url, _, ids := fixture(t)
	for _, refs := range [][]string{{"refs/heads/main"}, {"HEAD"}, {"refs/tags/tag-blob"}, {"refs/tags/tag", "refs/heads/main"}} {
		r, e := scsnative.CreateOptimized(filepath.Join(t.TempDir(), "selected.scs"))
		if e != nil {
			t.Fatal(e)
		}
		report, e := cloneFixture(context.Background(), r, url, Options{Name: "selected", Refs: refs})
		if e != nil {
			t.Fatal(refs, e)
		}
		c, e := r.GitCatalog("selected")
		if e != nil {
			t.Fatal(e)
		}
		if len(c.Refs) != len(refs) {
			t.Fatal("unselected refs advertised as imported", c.Refs, refs)
		}
		if report.Objects >= uint64(len(ids)) {
			t.Fatal("selected ingestion requested unrelated tagged objects", refs, report.Objects)
		}
		if len(refs) == 1 && refs[0] == "refs/heads/main" && c.Head != ids["commit"] {
			t.Fatal(c.Head)
		}
		for name, id := range c.Refs {
			if name != refs[0] && len(refs) == 1 {
				t.Fatal(c.Refs)
			}
			oid, e := repo.ParseGitOID(id)
			if e != nil {
				t.Fatal(e)
			}
			if e = r.VerifyGitObject(oid); e != nil {
				t.Fatal(e)
			}
		}
		if e = r.Close(); e != nil {
			t.Fatal(e)
		}
	}
	r, e := scsnative.CreateOptimized(filepath.Join(t.TempDir(), "missing.scs"))
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if _, e = cloneFixture(context.Background(), r, url, Options{Name: "missing", Refs: []string{"refs/heads/absent"}}); e == nil {
		t.Fatal("missing ref accepted")
	}
	if _, e = r.GitCatalog("missing"); e == nil {
		t.Fatal("missing selection published")
	}
}
