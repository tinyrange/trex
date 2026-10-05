package repo

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOptimizedHistoryCheckpointAndEdits(t *testing.T) {
	name := filepath.Join(t.TempDir(), "native.scs")
	r, err := createTestOptimized(name)
	must(t, err)
	base := bytes.Repeat([]byte("shifted content\n"), 2000)
	oid, _, err := r.IngestGitBody(context.Background(), GitBlob, base, GitOID{}, nil, uint64(len(base)))
	must(t, err)
	ids := []GitOID{oid}
	bodies := [][]byte{bytes.Clone(base)}
	for i := 0; i < 40; i++ {
		next := append([]byte{byte(i)}, base...)
		ext := editExtents(base, next)
		oid, _, err = r.IngestGitBody(context.Background(), GitBlob, nil, oid, ext, uint64(len(next)))
		must(t, err)
		ids = append(ids, oid)
		bodies = append(bodies, next)
		base = next
	}
	w := r.Empty()
	must(t, w.LinkGitBlob("f", oid, 0100755))
	snap, err := w.Publish("main")
	must(t, err)
	must(t, r.Checkpoint())
	stats, err := r.StorageStats()
	must(t, err)
	if stats.MaxDeltaDepth > maxBodyDepth || stats.MaxDeltaDepth == 0 {
		t.Fatal(stats)
	}
	must(t, r.Close())
	r, err = openTest(name)
	must(t, err)
	defer r.Close()
	for i, id := range ids {
		_, got, err := r.ReadGitObject(id)
		must(t, err)
		if !bytes.Equal(got, bodies[i]) {
			t.Fatal("changed body", i)
		}
	}
	must(t, r.Scrub(true))
	w, err = r.Fork(snap)
	must(t, err)
	reader, err := w.OpenReader("f")
	must(t, err)
	defer reader.Close()
	next := append([]byte("insert"), base...)
	must(t, w.WriteFile("f", next))
	st, err := w.Stat("f")
	must(t, err)
	if st.Body == "" || r.objects[key(st.Body)].depth == 0 {
		t.Fatal("edit did not share base")
	}
	b := make([]byte, 32)
	_, err = reader.ReadAt(b, 200)
	must(t, err)
	if !bytes.Equal(b, base[200:232]) {
		t.Fatal("reader changed after edit")
	}
	_, err = w.Publish("edit")
	must(t, err)
	must(t, r.Close())
	// Appending after the checkpoint must not hide newer publications.
	r, err = openTest(name)
	must(t, err)
	w, err = r.Checkout("edit")
	must(t, err)
	readEquals(t, w, "f", next)
	must(t, r.Checkpoint())
	must(t, r.Close())
}
func TestOptimizedCheckpointTornTailAndCorruption(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "base")
	r, err := createTestOptimized(name)
	must(t, err)
	w := r.Empty()
	must(t, w.WriteFile("f", bytes.Repeat([]byte("hello"), 1000)))
	_, err = w.Publish("main")
	must(t, err)
	before, err := r.StorageStats()
	must(t, err)
	must(t, r.Checkpoint())
	must(t, r.Close())
	raw, err := os.ReadFile(name)
	must(t, err)
	// Every byte boundary of the checkpoint footer must recover the last publication.
	for cut := len(raw) - checkpointFooterSize; cut < len(raw); cut++ {
		p := filepath.Join(dir, "cut")
		must(t, os.WriteFile(p, raw[:cut], 0600))
		r, err := openTest(p)
		must(t, err)
		w, err := r.Checkout("main")
		must(t, err)
		readEquals(t, w, "f", bytes.Repeat([]byte("hello"), 1000))
		must(t, r.Close())
	}
	// Checksummed checkpoint corruption is not silently accepted.
	bad := bytes.Clone(raw)
	bad[before.FileBytes+headerSize] ^= 1
	p := filepath.Join(dir, "badindex")
	must(t, os.WriteFile(p, bad, 0600))
	if r, e := openTest(p); e == nil {
		r.Close()
		t.Fatal("corrupt checkpoint accepted")
	}
	// A fast open need not read old payloads, but reads and scrubs must reject them.
	bad = bytes.Clone(raw)
	bad[len(magic)+headerSize+42] ^= 1
	p = filepath.Join(dir, "badbody")
	must(t, os.WriteFile(p, bad, 0600))
	r, err = openTest(p)
	must(t, err)
	w, err = r.Checkout("main")
	must(t, err)
	if _, err = w.ReadFile("f"); err == nil {
		t.Fatal("corrupt body accepted")
	}
	if err = r.Scrub(false); err == nil {
		t.Fatal("scrub missed corruption")
	}
	must(t, r.Close())
}
func TestNativeExtentBounds(t *testing.T) {
	for _, ext := range [][]Extent{{{Offset: 2, Length: 2}}, {{Length: 4, Data: []byte("x")}}, {{Offset: ^uint64(0), Length: 1}}, {{Length: ^uint64(0)}}} {
		if _, err := ApplyExtents([]byte("abc"), ext, 3); err == nil {
			t.Fatal("invalid extent accepted")
		}
	}
	r, err := createTestOptimized(filepath.Join(t.TempDir(), "f"))
	must(t, err)
	defer r.Close()
	_, _, err = r.IngestGitBody(context.Background(), GitBlob, nil, GitOID{}, nil, 0)
	must(t, err)
	must(t, r.Checkpoint())
	must(t, r.Scrub(true))

}
