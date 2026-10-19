// Package native owns native backing resources for portable block devices.
package native

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/tinyrange/trex/block"
)

// TemporaryOverlay is a disposable sparse file, not an independently bootable
// disk. Close only after every device user has stopped. Close removes its file;
// process crashes/SIGKILL can leave an orphan (never reused automatically).
type TemporaryOverlay struct {
	*block.SparseOverlay
	file     *os.File
	once     sync.Once
	closeErr error
}

// NewTemporaryOverlay creates a unique mode-0600 file in the explicit directory.
// There is no fallback directory or memory fallback. Truncate establishes only
// logical length; on a sparse-capable filesystem untouched chunks remain holes.
func NewTemporaryOverlay(base block.Device, dir string) (*TemporaryOverlay, error) {
	if dir == "" {
		return nil, errors.New("sparse overlay: explicit directory required")
	}
	if base == nil {
		return nil, errors.New("sparse overlay: base required")
	}
	f, err := os.CreateTemp(dir, "trex-overlay-*.sparse")
	if err != nil {
		return nil, fmt.Errorf("create temporary overlay (choose a writable -overlay-dir): %w", err)
	}
	overlay, err := block.NewSparseOverlay(base, f)
	if err == nil {
		err = f.Truncate(base.Geometry().Size)
	}
	if err != nil {
		return nil, errors.Join(err, f.Close(), os.Remove(f.Name()))
	}
	return &TemporaryOverlay{SparseOverlay: overlay, file: f}, nil
}
func (d *TemporaryOverlay) Path() string { return d.file.Name() }
func (d *TemporaryOverlay) Close() error {
	d.once.Do(func() { d.closeErr = errors.Join(d.Err(), d.file.Close(), os.Remove(d.file.Name())) })
	return d.closeErr
}
