//go:build linux

package native

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/tinyrange/trex/block"
)

type invalidBase struct{ largeBase }

func (invalidBase) Geometry() block.Geometry { return block.Geometry{Size: -1} }

type largeBase struct{}

func (largeBase) Geometry() block.Geometry {
	return block.Geometry{Size: 8 << 30, LogicalBlockSize: 512}
}
func (largeBase) Capabilities() block.Capabilities { return block.Capabilities{} }
func (largeBase) ReadAt(p []byte, _ int64) (int, error) {
	for i := range p {
		p[i] = 0x5a
	}
	return len(p), nil
}
func TestTemporarySparseAllocationAndCleanup(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "keep")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	d, err := NewTemporaryOverlay(largeBase{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	info, err := os.Stat(d.Path())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 || info.Size() != 8<<30 {
		t.Fatal(info)
	}
	if info.Sys().(*syscall.Stat_t).Blocks != 0 {
		t.Fatal("truncate allocated base image")
	}
	for _, off := range []int64{17, (8 << 30) - 5} {
		if _, err := d.WriteAt([]byte{1, 2, 3}, off); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Flush(); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(d.Path())
	if err != nil {
		t.Fatal(err)
	}
	allocated := info.Sys().(*syscall.Stat_t).Blocks * 512
	if allocated == 0 || allocated > 64<<10 {
		t.Fatalf("not sparse: %d physical bytes", allocated)
	}
	if d.DirtyBytes() != 8192 {
		t.Fatal(d.DirtyBytes())
	}
	t.Logf("logical=%d allocated=%d dirty=%d", info.Size(), allocated, d.DirtyBytes())
	p := make([]byte, 6)
	if _, err := d.ReadAt(p, 16); err != nil {
		t.Fatal(err)
	}
	if string(p) != string([]byte{0x5a, 1, 2, 3, 0x5a, 0x5a}) {
		t.Fatal(p)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal("repeat close", err)
	}
	if _, err := os.Stat(d.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("overlay retained", err)
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "untouched" {
		t.Fatal("unrelated file modified")
	}
	// Constructor failure cleans only its own new file.
	if _, err := NewTemporaryOverlay(invalidBase{}, dir); err == nil {
		t.Fatal("invalid geometry accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("constructor leaked file", entries, err)
	}
	if _, err := NewTemporaryOverlay(largeBase{}, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("silent directory fallback")
	}
}
