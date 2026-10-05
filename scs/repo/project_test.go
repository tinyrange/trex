package repo

import (
	"bytes"
	"github.com/tinyrange/trex/storage"
	"io"
	"testing"
)

func TestProjectReadersShareImmutableBodies(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(4 << 20))
	must(t, e)
	defer r.Close()
	w := r.Empty()
	data := bytes.Repeat([]byte("unchanged body\n"), 1024)
	must(t, w.WriteFile("source", data))
	a, e := w.OpenReader("source")
	must(t, e)
	defer a.Close()
	b, e := w.OpenReader("source")
	must(t, e)
	defer b.Close()
	buf := make([]byte, 8)
	_, e = a.ReadAt(buf, 0)
	must(t, e)
	_, e = b.ReadAt(buf, 0)
	must(t, e)
	if len(a.cached) == 0 || &a.cached[0] != &b.cached[0] {
		t.Fatal("readers duplicate immutable decoded body")
	}
	public, e := w.ReadFile("source")
	must(t, e)
	public[0] = '!'
	data[0] = '?'
	_, e = b.ReadAt(buf, 0)
	must(t, e)
	if string(buf) != "unchange" {
		t.Fatal("mutable input/public read aliases cached content", string(buf))
	}
	view := w.View()
	tree, e := w.SnapshotTree()
	must(t, e)
	before := r.end
	bodies := len(r.objects)
	must(t, w.WriteReader("copy", a))
	if r.end != before || len(r.objects) != bodies {
		t.Fatal("same-repository copy wrote payload")
	}
	must(t, w.WriteFile("source", []byte("new version")))
	stable, e := tree.OpenFile("source")
	must(t, e)
	got := make([]byte, 8)
	_, e = stable.ReadAt(got, 0)
	must(t, e)
	if string(got) != "unchange" {
		t.Fatal("captured tree follows live mutation")
	}
	if _, e = view.Stat("copy"); e == nil {
		t.Fatal("view follows live mutation")
	}
	// Eviction must not invalidate bytes already held by an immutable reader.
	r.mu.Lock()
	clear(r.codec.cache)
	r.codec.lru.Init()
	r.codec.bytes = 0
	r.mu.Unlock()
	old, e := io.ReadAll(a)
	must(t, e)
	if string(old[:8]) != "unchange" {
		t.Fatal("eviction invalidated reader")
	}
	fresh, e := view.OpenReader("source")
	must(t, e)
	defer fresh.Close()
	_, e = fresh.ReadAt(buf, 0)
	must(t, e)
	if string(buf) != "unchange" {
		t.Fatal("eviction reload corrupted body")
	}

}
