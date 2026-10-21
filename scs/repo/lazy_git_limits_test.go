package repo

import (
	"context"
	"github.com/tinyrange/trex/storage"
	"strings"
	"testing"
)

func TestLazyGitPublicationRejectsUnrepresentableTrees(t *testing.T) {
	for _, kind := range []string{"duplicate", "deep", "long"} {
		t.Run(kind, func(t *testing.T) {
			r, e := CreateOptimized(storage.NewMemoryStore(4 << 20))
			must(t, e)
			defer r.Close()
			blob := putLazyFixture(t, r, GitBlob, []byte("f"))
			var root GitOID
			switch kind {
			case "duplicate":
				data := gitTreeFixture("100644", "f", blob)
				root = putLazyFixture(t, r, GitTree, append(data, data...))
			case "deep":
				root = putLazyFixture(t, r, GitTree, nil)
				for i := 0; i < 258; i++ {
					root = putLazyFixture(t, r, GitTree, gitTreeFixture("40000", "d", root))
				}
			case "long":
				root = putLazyFixture(t, r, GitTree, gitTreeFixture("100644", strings.Repeat("x", 4097), blob))
			}
			must(t, r.PublishGit(GitCatalog{Name: "fixture", Head: root.String(), Refs: map[string]string{}}))
			w, e := r.CheckoutGit(context.Background(), "fixture", "HEAD")
			must(t, e)
			if _, e = w.Publish("invalid"); e == nil {
				t.Fatal("unrepresentable tree published")
			}
			if len(r.Refs()) != 0 {
				t.Fatal("invalid tree visible as ref")
			}
		})
	}
}
