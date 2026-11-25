package star

import (
	"fmt"
	"go.starlark.net/starlark"
	"io"
	"sync"
)

// observedDevice measures the guest-facing boundary without adding storage or
// changing capabilities. In particular sparse/native overlays keep their own
// durability, failure and lifecycle semantics.
type observedDevice struct {
	base                                                  BlockDevice
	mu                                                    sync.Mutex
	reads, writes, readBytes, writeBytes, errors, flushes int64
	readCoverage, writeCoverage                           byteCoverage
}

func blockObserveBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	limit := 262144
	if err := starlark.UnpackArgs("observe", args, kwargs, "base", &value, "coverage_ranges?", &limit); err != nil {
		return nil, err
	}
	base, err := AsDevice(value)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > 1048576 {
		return nil, fmt.Errorf("observe: coverage_ranges must be 1..1048576")
	}
	return NewValue("observed", &observedDevice{base: base, readCoverage: byteCoverage{limit: limit}, writeCoverage: byteCoverage{limit: limit}}), nil
}
func (d *observedDevice) Geometry() BlockGeometry         { return d.base.Geometry() }
func (d *observedDevice) Capabilities() BlockCapabilities { return d.base.Capabilities() }
func (d *observedDevice) record(write bool, off int64, n int, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil && err != io.EOF {
		d.errors++
	}
	if write {
		d.writes++
		d.writeBytes += int64(n)
		d.writeCoverage.add(off, int64(n))
	} else {
		d.reads++
		d.readBytes += int64(n)
		d.readCoverage.add(off, int64(n))
	}
}
func (d *observedDevice) ReadAt(p []byte, off int64) (int, error) {
	n, err := d.base.ReadAt(p, off)
	d.record(false, off, n, err)
	return n, err
}
func (d *observedDevice) WriteAt(p []byte, off int64) (int, error) {
	w, ok := d.base.(BlockDeviceWriter)
	if !ok {
		return 0, ErrBlockReadOnly
	}
	n, err := w.WriteAt(p, off)
	d.record(true, off, n, err)
	return n, err
}
func (d *observedDevice) Flush() error {
	f, ok := d.base.(BlockDeviceFlusher)
	if !ok {
		return ErrBlockUnsupported
	}
	err := f.Flush()
	d.mu.Lock()
	d.flushes++
	if err != nil {
		d.errors++
	}
	d.mu.Unlock()
	return err
}
func (d *observedDevice) ZeroAt(off, length int64) error {
	z, ok := d.base.(BlockDeviceZeroer)
	if !ok {
		return ErrBlockUnsupported
	}
	err := z.ZeroAt(off, length)
	n := 0
	if err == nil {
		n = int(length)
	}
	d.record(true, off, n, err)
	return err
}
func (d *observedDevice) TrimAt(off, length int64) error {
	t, ok := d.base.(BlockDeviceTrimmer)
	if !ok {
		return ErrBlockUnsupported
	}
	return t.TrimAt(off, length)
}
func (d *observedDevice) Extents(off, length int64) ([]BlockExtent, error) {
	e, ok := d.base.(BlockDeviceExtenter)
	if !ok {
		return nil, ErrBlockUnsupported
	}
	return e.Extents(off, length)
}
func (d *observedDevice) Prefetch(off, length int64) error {
	p, ok := d.base.(BlockDevicePrefetcher)
	if !ok {
		return ErrBlockUnsupported
	}
	return p.Prefetch(off, length)
}
func (d *observedDevice) Acquire() (func(), error) {
	if b, ok := d.base.(blockDeviceLease); ok {
		return b.Acquire()
	}
	return func() {}, nil
}
func (d *observedDevice) Done() <-chan struct{} {
	if b, ok := d.base.(interface{ Done() <-chan struct{} }); ok {
		return b.Done()
	}
	return nil
}
func (d *observedDevice) Err() error {
	if b, ok := d.base.(interface{ Err() error }); ok {
		return b.Err()
	}
	return nil
}
func (d *observedDevice) Stats() starlark.StringDict {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := starlark.StringDict{}
	if b, ok := d.base.(blockDeviceStats); ok {
		s = b.Stats()
	}
	if b, ok := d.base.(interface{ DirtyBytes() int64 }); ok {
		s["dirty_bytes"] = starlark.MakeInt64(b.DirtyBytes())
	}
	for k, v := range map[string]int64{"reads": d.reads, "writes": d.writes, "read_bytes": d.readBytes, "write_bytes": d.writeBytes, "unique_read_bytes": d.readCoverage.bytes, "unique_write_bytes": d.writeCoverage.bytes, "errors": d.errors, "flushes": d.flushes} {
		s[k] = starlark.MakeInt64(v)
	}
	s["coverage_enabled"] = starlark.True
	s["coverage_complete"] = starlark.Bool(!d.readCoverage.overflow && !d.writeCoverage.overflow)
	return s
}
