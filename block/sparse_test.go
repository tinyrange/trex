package block

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"sync"
	"testing"
)

type sparseTestBase []byte

func (b sparseTestBase) ReadAt(p []byte, o int64) (int, error) {
	return bytes.NewReader(b).ReadAt(p, o)
}
func (b sparseTestBase) Geometry() Geometry {
	return Geometry{Size: int64(len(b)), LogicalBlockSize: 512}
}
func (b sparseTestBase) Capabilities() Capabilities { return Capabilities{} }

type sparseTestBacking struct {
	data    []byte
	writes  int
	fault   error
	short   bool
	syncErr error
	readErr error
}

func (b *sparseTestBacking) ReadAt(p []byte, o int64) (int, error) {
	if b.readErr != nil {
		return 0, b.readErr
	}
	return bytes.NewReader(b.data).ReadAt(p, o)
}
func (b *sparseTestBacking) WriteAt(p []byte, o int64) (int, error) {
	b.writes++
	if b.fault != nil || b.short {
		n := copy(b.data[o:], p[:len(p)/2])
		return n, b.fault
	}
	return copy(b.data[o:], p), nil
}
func (b *sparseTestBacking) Sync() error { return b.syncErr }
func sparseFixture(t *testing.T, size int) (*SparseOverlay, *sparseTestBacking, []byte) {
	t.Helper()
	base := make(sparseTestBase, size)
	for i := range base {
		base[i] = byte(i*31 + 17)
	}
	backing := &sparseTestBacking{data: make([]byte, size)}
	d, err := NewSparseOverlay(base, backing)
	if err != nil {
		t.Fatal(err)
	}
	return d, backing, base
}
func TestSparseDifferential(t *testing.T) {
	d, _, base := sparseFixture(t, 13*4096+137)
	original := bytes.Clone(base)
	want := bytes.Clone(base)
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 600; i++ {
		off := rng.Intn(len(want))
		size := rng.Intn(min(7000, len(want)-off) + 1)
		data := make([]byte, size)
		rng.Read(data)
		if i%5 == 0 {
			copy(data, base[off:off+size])
		}
		if n, err := d.WriteAt(data, int64(off)); err != nil || n != len(data) {
			t.Fatalf("write %d: %d %v", i, n, err)
		}
		copy(want[off:], data)
		got := make([]byte, len(want))
		if _, err := d.ReadAt(got, 0); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("mismatch at operation %d", i)
		}
	}
	if !bytes.Equal(base, original) {
		t.Fatal("base mutated")
	}
	if err := d.Flush(); err != nil {
		t.Fatal(err)
	}
}
func TestSparseUnchangedAndNoQuota(t *testing.T) {
	d, b, base := sparseFixture(t, 3*4096)
	if _, err := d.WriteAt(base, 0); err != nil {
		t.Fatal(err)
	}
	if b.writes != 0 || d.DirtyBytes() != 0 {
		t.Fatal("unchanged write allocated")
	}
	if _, err := d.WriteAt([]byte{99}, 4095); err != nil {
		t.Fatal(err)
	}
	if _, err := d.WriteAt(base[:4096], 0); err != nil {
		t.Fatal(err)
	}
	if d.DirtyBytes() != 4096 {
		t.Fatal("revert incorrectly freed allocation accounting")
	}
	// Every address in the virtual disk remains writable regardless of how many
	// other chunks changed. Only the backing store can run out of space.
	data := bytes.Repeat([]byte{55}, len(base))
	if n, err := d.WriteAt(data, 0); err != nil || n != len(data) {
		t.Fatalf("whole disk: %d %v", n, err)
	}
	if d.DirtyBytes() != int64(len(base)) {
		t.Fatal(d.DirtyBytes())
	}
	got := make([]byte, len(data))
	if _, err := d.ReadAt(got, 0); err != nil || !bytes.Equal(got, data) {
		t.Fatal("readback", err)
	}
}

func TestSparseFailuresAreTerminal(t *testing.T) {
	injected := errors.New("no space")
	for _, kind := range []string{"write", "short", "sync", "read"} {
		t.Run(kind, func(t *testing.T) {
			d, b, _ := sparseFixture(t, 8192)
			if _, err := d.WriteAt([]byte{1}, 0); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "write":
				b.fault = injected
			case "short":
				b.short = true
			case "sync":
				b.syncErr = injected
			case "read":
				b.readErr = injected
			}
			var err error
			switch kind {
			case "sync":
				err = d.Flush()
			case "read":
				_, err = d.ReadAt(make([]byte, 1), 0)
			default:
				_, err = d.WriteAt(bytes.Repeat([]byte{2}, 32), 0)
			}
			expected := injected
			if kind == "short" {
				expected = io.ErrShortWrite
			}
			if !errors.Is(err, expected) {
				t.Fatalf("failure: %v", err)
			}
			if _, err = d.WriteAt([]byte{2}, 4096); !errors.Is(err, expected) {
				t.Fatal("write after failure", err)
			}
			if _, err = d.ReadAt(make([]byte, 1), 0); !errors.Is(err, expected) {
				t.Fatal("read after partial write", err)
			}
			if err = d.Flush(); !errors.Is(err, expected) {
				t.Fatal("flush after failure", err)
			}
		})
	}
}
func TestSparseRangesAndConcurrentIO(t *testing.T) {
	d, _, _ := sparseFixture(t, 16*4096)
	for _, off := range []int64{-1, 16 * 4096, 1 << 62} {
		if _, err := d.WriteAt([]byte{1}, off); !errors.Is(err, ErrOutOfRange) {
			t.Fatal(off, err)
		}
	}
	if n, err := d.WriteAt(nil, 16*4096); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := bytes.Repeat([]byte{byte(i)}, 4096)
			for j := 0; j < 20; j++ {
				if _, err := d.WriteAt(data, int64(i*4096)); err != nil {
					t.Error(err)
					return
				}
				got := make([]byte, 4096)
				if _, err := d.ReadAt(got, int64(i*4096)); err != nil || !bytes.Equal(got, data) {
					t.Error("concurrent I/O", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
