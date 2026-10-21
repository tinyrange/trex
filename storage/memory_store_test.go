package storage

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
)

func TestMemoryStoreSnapshotsTruncationAndLimit(t *testing.T) {
	m := NewMemoryStore(3 * memoryPageBytes)
	data := []byte("original")
	off := int64(memoryPageBytes - 3)
	if _, err := m.WriteAt(data, off); err != nil {
		t.Fatal(err)
	}
	first, err := m.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	// A snapshot shares pages, not a copied full logical file.
	snap := first.(*memorySnapshot)
	if len(m.pages) != 2 || snap.pages[0] != m.pages[0] {
		t.Fatal("snapshot lost sparse page sharing")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			b := make([]byte, len(data))
			n, e := first.ReadAt(b, off)
			if e != nil || n != len(b) || !bytes.Equal(b, data) {
				t.Errorf("snapshot changed: %q %v", b, e)
				return
			}
		}
	}()
	if _, err := m.WriteAt([]byte("changed!"), off); err != nil {
		t.Fatal(err)
	}
	if m.pages[0] == snap.pages[0] {
		t.Fatal("write did not copy shared page")
	}
	if err := m.Truncate(off + 2); err != nil {
		t.Fatal(err)
	}
	if err := m.Truncate(off + 8); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 8)
	if _, err := m.ReadAt(b, off); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, append([]byte("ch"), make([]byte, 6)...)) {
		t.Fatalf("truncated bytes reappeared: %q", b)
	}
	size, _ := m.Length()
	if n, e := m.WriteAt([]byte("out of bounds"), 3*memoryPageBytes-1); n != 0 || !errors.Is(e, ErrStoreLimit) {
		t.Fatal(n, e)
	}
	if after, _ := m.Length(); after != size {
		t.Fatal("failed write changed size")
	}
	gap := make([]byte, 10)
	if _, err := m.ReadAt(gap, 0); err != nil || !bytes.Equal(gap, make([]byte, 10)) {
		t.Fatal("sparse hole", err)
	}
	wg.Wait()
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReadAt(b, off); !errors.Is(err, ErrStoreClosed) {
		t.Fatal(err)
	}
	if n, err := first.ReadAt(b, off); err != nil || n != 8 || string(b) != "original" {
		t.Fatal("snapshot after close", n, err, string(b))
	}
	if n, err := first.ReadAt(make([]byte, 9), off); n != 8 || err != io.EOF {
		t.Fatal(n, err)
	}
}
