package repo

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"path/filepath"
	"testing"
)

func TestChangedEncodingDoesNotReuseVerification(t *testing.T) {
	r, err := createTestOptimized(filepath.Join(t.TempDir(), "proof.scs"))
	must(t, err)
	defer r.Close()
	w := r.Empty()
	data := bytes.Repeat([]byte("x"), 4000)
	must(t, w.WriteFile("f", data))
	must(t, r.sync())
	st, err := w.Stat("f")
	must(t, err)
	loc := r.objects[key(st.Body)]
	encoded := make([]byte, loc.stored)
	_, err = r.f.ReadAt(encoded, loc.offset)
	must(t, err)
	// Construct a different, valid compressed frame and physical checksum while
	// keeping the old native canonical ID. A previous proof must not validate it.
	bad := r.bodyCodec().enc.EncodeAll(nativeOps([]Extent{{Length: 4000, Data: bytes.Repeat([]byte("y"), 4000)}}), bytes.Clone(encoded[:42]))
	sum := sha256.Sum256(bad)
	bad = append(bad, sum[:]...)
	if len(bad) != len(encoded) {
		t.Fatal("fixture encoding sizes differ")
	}
	_, err = r.f.WriteAt(bad, loc.offset)
	must(t, err)
	r.codec.cache = map[objectKey]*list.Element{}
	r.codec.lru.Init()
	r.codec.bytes = 0
	if _, err = w.ReadFile("f"); err == nil {
		t.Fatal("old verification accepted changed canonical content")
	}
}
