package repo

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"path/filepath"
	"testing"
)

func TestOptimizedIdentityNamespacesShareBody(t *testing.T) {
	name := filepath.Join(t.TempDir(), "ids.scs")
	r, err := createTestOptimized(name)
	must(t, err)
	data := []byte("one native body in two Git namespaces\n")
	var ids []GitOID
	for _, n := range []int{20, 32} {
		var h hash.Hash = sha1.New()
		if n == 32 {
			h = sha256.New()
		}
		fmt.Fprintf(h, "blob %d%c", len(data), 0)
		h.Write(data)
		id, _ := GitOIDFromBytes(h.Sum(nil))
		ids = append(ids, id)
		_, err := r.PutGitObject(context.Background(), id, GitBlob, int64(len(data)), bytes.NewReader(data))
		must(t, err)
	}
	s, err := r.StorageStats()
	must(t, err)
	if s.NativeBodies != 1 || r.GitStatistics().Objects != 2 {
		t.Fatal(s, r.GitStatistics())
	}
	must(t, r.Checkpoint())
	must(t, r.Close())
	for _, open := range []func(string) (*Repository, error){openTest, openTestVerified} {
		r, err = open(name)
		must(t, err)
		for _, id := range ids {
			must(t, r.VerifyGitObject(id))
			_, b, e := r.ReadGitObject(id)
			must(t, e)
			if !bytes.Equal(b, data) {
				t.Fatal("namespace body mismatch")
			}
		}
		must(t, r.Close())
	}
}
