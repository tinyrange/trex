package block

import (
	"bytes"
	"errors"
	"testing"
)

type sparseReadBase struct {
	sparseTestBase
	calls int
}

func (b *sparseReadBase) ReadAt(p []byte, off int64) (int, error) {
	b.calls++
	return b.sparseTestBase.ReadAt(p, off)
}

type sparseReadBacking struct {
	sparseTestBacking
	calls int
	limit int
	err   error
}

func (b *sparseReadBacking) ReadAt(p []byte, off int64) (int, error) {
	b.calls++
	if b.err != nil {
		n, _ := b.sparseTestBacking.ReadAt(p[:min(len(p), b.limit)], off)
		return n, b.err
	}
	return b.sparseTestBacking.ReadAt(p, off)
}

func TestSparseReadRuns(t *testing.T) {
	const size = 16*4096 + 137
	base := &sparseReadBase{sparseTestBase: bytes.Repeat([]byte{17}, size)}
	backing := &sparseReadBacking{sparseTestBacking: sparseTestBacking{data: make([]byte, size)}}
	d, err := NewSparseOverlay(base, backing)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, size-27)
	if n, err := d.ReadAt(got, 27); err != nil || n != len(got) || !bytes.Equal(got, base.sparseTestBase[27:]) {
		t.Fatal("clean read", n, err)
	}
	if base.calls != 1 || backing.calls != 0 {
		t.Fatalf("clean I/O amplified: base=%d backing=%d", base.calls, backing.calls)
	}
	// A dirty middle run must not leak the unwritten backing holes on either side.
	changed := bytes.Repeat([]byte{91}, 8*4096)
	if _, err := d.WriteAt(changed, 3*4096); err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(base.sparseTestBase)
	copy(want[3*4096:], changed)
	base.calls, backing.calls = 0, 0
	if n, err := d.ReadAt(got, 27); err != nil || n != len(got) || !bytes.Equal(got, want[27:]) {
		t.Fatal("mixed read", n, err)
	}
	if base.calls != 2 || backing.calls != 1 {
		t.Fatalf("mixed I/O amplified: base=%d backing=%d", base.calls, backing.calls)
	}
	// A partial backing failure reports the clean prefix plus the actual bytes,
	// and remains terminal even for subsequent reads wholly outside that run.
	injected := errors.New("backing read failure")
	backing.limit, backing.err = 5000, injected
	n, err := d.ReadAt(got, 27)
	if n != 3*4096-27+5000 || !errors.Is(err, injected) {
		t.Fatalf("partial read: %d %v", n, err)
	}
	if !bytes.Equal(got[:n], want[27:27+n]) {
		t.Fatal("partial read data")
	}
	select {
	case <-d.Done():
	default:
		t.Fatal("failure not terminal")
	}
	if n, err := d.ReadAt(make([]byte, 1), 0); n != 0 || !errors.Is(err, injected) {
		t.Fatal("read after failure", n, err)
	}
}
