package repo

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"path/filepath"
	"testing"
)

func TestGitCanonicalStorage(t *testing.T) {
	r, err := createTest(filepath.Join(t.TempDir(), "git.scs"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx := context.Background()
	data := append(bytes.Repeat([]byte("x"), BlockSize), bytes.Repeat([]byte("y"), BlockSize+11)...)
	for _, n := range []int{20, 32} {
		var h hash.Hash = sha1.New()
		if n == 32 {
			h = sha256.New()
		}
		fmt.Fprintf(h, "blob %d%c", len(data), 0)
		h.Write(data)
		id, _ := GitOIDFromBytes(h.Sum(nil))
		if _, err = r.PutGitObject(ctx, id, GitBlob, int64(len(data)), bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		if err = r.VerifyGitObject(id); err != nil {
			t.Fatal(err)
		}
		rd, err := r.OpenGitObject(id)
		if err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 37)
		if n, e := rd.ReadAt(b, BlockSize-13); n != len(b) || e != nil || !bytes.Equal(b, data[BlockSize-13:BlockSize+24]) {
			t.Fatal("cross-block read", n, e)
		}
		if _, e := rd.Seek(-11, io.SeekEnd); e != nil {
			t.Fatal(e)
		}
		b, e := io.ReadAll(rd)
		if e != nil || !bytes.Equal(b, data[len(data)-11:]) {
			t.Fatal("seek", e)
		}
		rd.Close()
	}
	stats, err := r.StorageStats()
	if err != nil || stats.UniqueBlocks != 3 {
		t.Fatal("SHA namespaces failed to share native chunks", stats, err)
	}
	w := r.Empty()
	if err = w.WriteFile("f", data); err != nil {
		t.Fatal(err)
	}
	rd, err := w.OpenReader("f")
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	if err = w.WriteFile("f", []byte("changed")); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rd)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("reader changed after mutation", err)
	}
	bad, _ := ParseGitOID("1111111111111111111111111111111111111111")
	if _, err = r.PutGitObject(ctx, bad, GitBlob, 3, bytes.NewReader([]byte("bad"))); err == nil {
		t.Fatal("wrong digest accepted")
	}
	if _, _, ok := r.GitObjectHeader(bad); ok {
		t.Fatal("invalid object registered")
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = r.PutGitObject(cancelCtx, bad, GitBlob, 0, bytes.NewReader(nil)); err == nil {
		t.Fatal("cancellation ignored")
	}
}
