package repo

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectoryPageCanonicalHistory(t *testing.T) {
	r, name := newRepo(t)
	names := []string{"ä", "alpha", strings.Repeat("z", 4096)}
	for i := 0; i < 500; i++ {
		names = append(names, fmt.Sprintf("file-%04d", i))
	}
	a, b := r.Empty(), r.Empty()
	for _, name := range names {
		must(t, a.WriteFile(name, []byte(name)))
	}
	rng := rand.New(rand.NewSource(13))
	order := rng.Perm(len(names))
	for _, i := range order {
		must(t, b.WriteFile(names[i], []byte(names[i])))
	}
	first, err := a.Snapshot()
	must(t, err)
	second, err := b.Snapshot()
	must(t, err)
	if first != second {
		t.Fatal("directory ID depends on insertion order")
	}
	// Delete/reinsert across page boundaries and require the original identity.
	for _, name := range names[:80] {
		must(t, b.Delete(name))
	}
	for i := 79; i >= 0; i-- {
		must(t, b.WriteFile(names[i], []byte(names[i])))
	}
	second, err = b.Snapshot()
	must(t, err)
	if first != second {
		t.Fatal("directory ID depends on deletion history")
	}
	// Collapse branches by both entry count and encoded size (long-name case).
	for _, name := range names[2:] {
		must(t, b.Delete(name))
	}
	small := r.Empty()
	for _, name := range names[:2] {
		must(t, small.WriteFile(name, []byte(name)))
	}
	want, err := small.Snapshot()
	must(t, err)
	got, err := b.Publish("small")
	must(t, err)
	if got != want || b.s.root.children.slots != nil {
		t.Fatal("noncanonical branch collapse")
	}
	_, err = a.Publish("wide")
	must(t, err)
	must(t, r.Close())
	r, err = openTest(name)
	must(t, err)
	defer r.Close()
	restored, err := r.Checkout("wide")
	must(t, err)
	id, err := restored.Snapshot()
	must(t, err)
	if id != first {
		t.Fatal("paged tree identity changed on reload")
	}
	for _, name := range names {
		readEquals(t, restored, name, []byte(name))
	}
}

// Verify asymptotic work using bytes/records, not a machine-dependent timer.
func TestWideDirectoryIncrementalPages(t *testing.T) {
	for _, size := range []int{100, 10000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			r, filename := newRepo(t)
			w := r.Empty()
			for i := 0; i < size; i++ {
				must(t, w.WriteFile(fmt.Sprintf("file-%06d", i), []byte("base")))
			}
			base, err := w.Publish("main")
			must(t, err)
			for pass := 0; pass < 2; pass++ {
				if pass == 1 {
					must(t, r.Close())
					r, err = openTest(filename)
					must(t, err)
					defer r.Close()
					w, err = r.Checkout("main")
					must(t, err)
				}
				before, err := r.f.Stat()
				must(t, err)
				oldObjects := len(r.objects)
				oldPages := map[*childIndex]bool{}
				var visit func(*childIndex)
				visit = func(p *childIndex) {
					if p == nil {
						return
					}
					oldPages[p] = true
					if p.slots != nil {
						for _, c := range p.slots {
							visit(c)
						}
					}
				}
				visit(w.s.root.children)
				f, err := w.Fork()
				must(t, err)
				must(t, f.WriteFile("file-000050", []byte(fmt.Sprintf("edit-%d", pass))))
				id, err := f.Snapshot()
				must(t, err)
				if id == base {
					t.Fatal("changed tree retained ID")
				}
				after, err := r.f.Stat()
				must(t, err)
				if after.Size()-before.Size() > 16384 || len(r.objects)-oldObjects > 16 {
					t.Fatalf("edit rewrote too much: %d bytes, %d objects", after.Size()-before.Size(), len(r.objects)-oldObjects)
				}
				shared, newPages := 0, 0
				var check func(*childIndex)
				check = func(p *childIndex) {
					if p == nil {
						return
					}
					if oldPages[p] {
						shared++
						return
					}
					newPages++
					if p.slots != nil {
						for _, c := range p.slots {
							check(c)
						}
					}
				}
				check(f.s.root.children)
				if shared == 0 || newPages > 8 {
					t.Fatalf("insufficient page sharing: shared=%d new=%d", shared, newPages)
				}
				readEquals(t, w, "file-000050", []byte("base"))
				for _, loc := range r.objects {
					if loc.kind == indexKind && loc.size > maxIndexBytes {
						t.Fatal("unbounded directory page")
					}
				}
			}
		})
	}
}

func TestRejectV1WithoutChangingFile(t *testing.T) {
	name := filepath.Join(t.TempDir(), "old.scs")
	old := []byte("SCSREPO1keep these original bytes")
	must(t, os.WriteFile(name, old, 0600))
	if r, err := openTest(name); err == nil {
		r.Close()
		t.Fatal("accepted old format")
	} else if !strings.Contains(err.Error(), "SCSREPO1") {
		t.Fatal(err)
	}
	got, err := os.ReadFile(name)
	must(t, err)
	if !bytes.Equal(old, got) {
		t.Fatal("old repository was changed")
	}
}

func encodedLeaf(t *testing.T, r *Repository, name string) []byte {
	t.Helper()
	id, err := r.putJSON(fileKind, Entry{Kind: "file", Mode: 0644})
	must(t, err)
	data := []byte{0, 0, 1}
	data = binary.BigEndian.AppendUint16(data, uint16(len(name)))
	data = append(data, name...)
	data = append(data, 1, 1, 164) // file, 0644
	data, err = appendRawID(data, id)
	must(t, err)
	return data
}
func snapshotWithIndex(t *testing.T, r *Repository, data []byte) ID {
	t.Helper()
	page, err := r.append(indexKind, data)
	must(t, err)
	root, err := r.putJSON(treeKind, tree{Index: page})
	must(t, err)
	id, err := r.putJSON(snapshotKind, snapshot{Tree: root})
	must(t, err)
	return id
}
func TestMalformedDirectoryPages(t *testing.T) {
	cases := map[string]func(*testing.T, *Repository) []byte{
		"short":          func(_ *testing.T, _ *Repository) []byte { return []byte{0} },
		"unknown":        func(_ *testing.T, _ *Repository) []byte { return []byte{2, 0, 0} },
		"empty-leaf":     func(_ *testing.T, _ *Repository) []byte { return []byte{0, 0, 0} },
		"too-many":       func(_ *testing.T, _ *Repository) []byte { return []byte{0, 0, 33} },
		"truncated-name": func(_ *testing.T, _ *Repository) []byte { return []byte{0, 0, 1, 255, 255} },
		"empty-branch":   func(_ *testing.T, _ *Repository) []byte { return []byte{1, 0, 0} },
		"short-branch":   func(_ *testing.T, _ *Repository) []byte { return []byte{1, 0, 1} },
		"trailing":       func(t *testing.T, r *Repository) []byte { return append(encodedLeaf(t, r, "a"), 0) },
		"invalid-name":   func(t *testing.T, r *Repository) []byte { return encodedLeaf(t, r, "../bad") },
		"invalid-mode":   func(t *testing.T, r *Repository) []byte { b := encodedLeaf(t, r, "a"); b[7] = 255; return b },
		"invalid-kind":   func(t *testing.T, r *Repository) []byte { b := encodedLeaf(t, r, "a"); b[6] = 9; return b },
		"missing-child":  func(t *testing.T, r *Repository) []byte { b := encodedLeaf(t, r, "a"); clear(b[len(b)-32:]); return b },
		"duplicate": func(t *testing.T, r *Repository) []byte {
			b := encodedLeaf(t, r, "a")
			b[2] = 2
			return append(b, b[3:]...)
		},
		"unsorted": func(t *testing.T, r *Repository) []byte {
			b := encodedLeaf(t, r, "z")
			b[2] = 2
			return append(b, encodedLeaf(t, r, "a")[3:]...)
		},
		"wrong-partition": func(t *testing.T, r *Repository) []byte {
			id, err := r.append(indexKind, encodedLeaf(t, r, "a"))
			must(t, err)
			slot := (hashSlot(sha256.Sum256([]byte("a")), 0) + 1) % 16
			b := binary.BigEndian.AppendUint16([]byte{1}, uint16(1)<<slot)
			b, err = appendRawID(b, id)
			must(t, err)
			return b
		},
		"unnecessary-branch": func(t *testing.T, r *Repository) []byte {
			id, err := r.append(indexKind, encodedLeaf(t, r, "a"))
			must(t, err)
			slot := hashSlot(sha256.Sum256([]byte("a")), 0)
			b := binary.BigEndian.AppendUint16([]byte{1}, uint16(1)<<slot)
			b, err = appendRawID(b, id)
			must(t, err)
			return b
		},
	}
	for name, makePage := range cases {
		t.Run(name, func(t *testing.T) {
			r, _ := newRepo(t)
			id := snapshotWithIndex(t, r, makePage(t, r))
			if _, err := r.Fork(id); err == nil {
				t.Fatal("accepted malformed page")
			}
		})
	}
}

func TestDirectoryPageChecksum(t *testing.T) {
	r, name := newRepo(t)
	w := r.Empty()
	must(t, w.WriteFile("a", nil))
	_, err := w.Publish("main")
	must(t, err)
	page := w.s.root.children.id
	loc := r.objects[key(page)]
	_, err = r.f.WriteAt([]byte{255}, loc.offset)
	must(t, err)
	if _, err := r.Checkout("main"); err == nil {
		t.Fatal("ignored page checksum")
	}
	must(t, r.Close())
	if r, err = openTest(name); err == nil {
		r.Close()
		t.Fatal("corrupt page treated as recoverable tail")
	}
}

// A split replaces one leaf with multiple pages. Every byte cut in that update
// must expose the previous root until the complete new catalog is present.
func TestDirectoryPageSplitRecovery(t *testing.T) {
	r, name := newRepo(t)
	w := r.Empty()
	for i := 0; i < 32; i++ {
		must(t, w.WriteFile(fmt.Sprintf("f%02d", i), nil))
	}
	old, err := w.Publish("main")
	must(t, err)
	st, err := r.f.Stat()
	must(t, err)
	boundary := int(st.Size())
	must(t, w.WriteFile("split", nil))
	latest, err := w.Publish("main")
	must(t, err)
	must(t, r.Close())
	full, err := os.ReadFile(name)
	must(t, err)
	cutfile := filepath.Join(t.TempDir(), "cut.scs")
	for cut := boundary; cut <= len(full); cut++ {
		must(t, os.WriteFile(cutfile, full[:cut], 0600))
		recovered, err := openTest(cutfile)
		must(t, err)
		expected := old
		if cut == len(full) {
			expected = latest
		}
		if recovered.Refs()["main"] != expected {
			t.Fatalf("wrong root at cut %d", cut-boundary)
		}
		view, err := recovered.Checkout("main")
		must(t, err)
		paths := view.Paths()
		want := 32
		if cut == len(full) {
			want = 33
		}
		if len(paths) != want {
			t.Fatalf("partial directory at cut %d", cut-boundary)
		}
		must(t, view.WriteFile("after-recovery", nil))
		_, err = view.Publish("main")
		must(t, err)
		must(t, recovered.Close())
	}
}
