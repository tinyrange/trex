package star

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func testBlockDevice(t *testing.T, size int) *fileBlockDevice {
	t.Helper()
	data := make([]byte, size)
	for index := range data {
		data[index] = byte(index * 31)
	}
	device, err := newFileBlockDevice(&starfile.Bytes{Name: "block-test", Data: data}, 512, 512, false)
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func TestFileBlockDeviceSeparatesLogicalSectorAndMinimumTransfer(t *testing.T) {
	data := make([]byte, 4096)
	device, err := newFileBlockDevice(&starfile.Bytes{Name: "cd-test", Data: data}, 2048, 2048, false)
	if err != nil {
		t.Fatal(err)
	}
	geometry := device.Geometry()
	if geometry.LogicalBlockSize != 2048 || geometry.PhysicalBlockSize != 2048 || geometry.MinimumTransfer != 512 {
		t.Fatalf("file block geometry = %+v, want logical/physical 2048 and minimum transfer 512", geometry)
	}
	if _, err := device.ReadAt(make([]byte, 512), 512); err != nil {
		t.Fatalf("512-byte El Torito read: %v", err)
	}
}

func TestBlockOverlayIsolationCapacityLeaseAndCommit(t *testing.T) {
	base := testBlockDevice(t, 3*4096)
	overlay, err := newOverlayBlockDevice(base, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}

	want := []byte("overlay-data")
	if _, err := overlay.WriteAt(want, 700); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := overlay.ReadAt(got, 700); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("overlay read = %q, want %q", got, want)
	}
	baseData := make([]byte, len(want))
	if _, err := base.ReadAt(baseData, 700); err != nil {
		t.Fatal(err)
	}
	if string(baseData) == string(want) {
		t.Fatal("overlay write changed base device")
	}

	if _, err := overlay.WriteAt([]byte{1}, 4096); err == nil {
		t.Fatal("second dirty chunk did not exceed configured capacity")
	} else {
		var capacity *BlockCapacityError
		if !errors.As(err, &capacity) {
			t.Fatalf("capacity error = %T %v", err, err)
		}
	}

	release, err := overlay.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := overlay.Commit(); err == nil {
		t.Fatal("commit succeeded with active lease")
	}
	release()
	committed, err := overlay.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := overlay.WriteAt([]byte{2}, 700); !errors.Is(err, ErrBlockReadOnly) {
		t.Fatalf("write after commit = %v, want read-only", err)
	}
	got = make([]byte, len(want))
	if _, err := committed.ReadAt(got, 700); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("committed read = %q, want %q", got, want)
	}
}

func TestBlockOverlaySnapshotRemainsImmutableDuringActiveLease(t *testing.T) {
	base := testBlockDevice(t, 2*4096)
	overlay, err := newOverlayBlockDevice(base, 2*4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := overlay.WriteAt([]byte("before"), 700); err != nil {
		t.Fatal(err)
	}
	release, err := overlay.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	snapshot, err := overlay.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := overlay.WriteAt([]byte("after!"), 700); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, 6)
	if _, err := snapshot.ReadAt(got, 700); err != nil {
		t.Fatal(err)
	}
	if string(got) != "before" {
		t.Fatalf("snapshot read = %q, want before", got)
	}
	if _, err := overlay.ReadAt(got, 700); err != nil {
		t.Fatal(err)
	}
	if string(got) != "after!" {
		t.Fatalf("live overlay read = %q, want after!", got)
	}
	if _, err := snapshot.WriteAt([]byte{1}, 0); !errors.Is(err, ErrBlockReadOnly) {
		t.Fatalf("snapshot write = %v, want read-only", err)
	}
	stats := overlay.Stats()
	if got, _ := stats["snapshots"].(starlark.Int).Uint64(); got != 1 {
		t.Fatalf("snapshot count = %d, want 1", got)
	}
	if got, _ := stats["copy_on_write_bytes"].(starlark.Int).Uint64(); got != 4096 {
		t.Fatalf("copy-on-write bytes = %d, want 4096", got)
	}
}

func TestBlockOverlayZeroCapacityFailureIsAtomic(t *testing.T) {
	base := testBlockDevice(t, 3*4096)
	overlay, err := newOverlayBlockDevice(base, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	before := make([]byte, 8192)
	if _, err := overlay.ReadAt(before, 0); err != nil {
		t.Fatal(err)
	}
	if err := overlay.ZeroAt(0, 8192); err == nil {
		t.Fatal("zero spanning too many chunks succeeded")
	}
	after := make([]byte, len(before))
	if _, err := overlay.ReadAt(after, 0); err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed zero operation changed overlay contents")
	}
}

func TestBlockOverlayElidesBaseEquivalentWritesAndZeroes(t *testing.T) {
	base, err := newFileBlockDevice(&starfile.Bytes{Name: "zero-base", Data: make([]byte, 3*4096)}, 512, 512, false)
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := newOverlayBlockDevice(base, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := overlay.WriteAt(make([]byte, 8192), 0); err != nil {
		t.Fatalf("base-equivalent write exceeded capacity: %v", err)
	}
	if err := overlay.ZeroAt(4096, 8192); err != nil {
		t.Fatalf("base-equivalent zero exceeded capacity: %v", err)
	}
	if got := overlay.dirtyBytes; got != 0 {
		t.Fatalf("base-equivalent operations retained %d dirty bytes", got)
	}
	if _, err := overlay.WriteAt([]byte{1}, 5000); err != nil {
		t.Fatal(err)
	}
	if got := overlay.dirtyBytes; got != 4096 {
		t.Fatalf("changed write retained %d dirty bytes, want 4096", got)
	}
	if _, err := overlay.WriteAt(make([]byte, 4096), 4096); err != nil {
		t.Fatal(err)
	}
	if got := overlay.dirtyBytes; got != 0 {
		t.Fatalf("restoring base retained %d dirty bytes", got)
	}
}

func TestBlockOverlayElisionPreservesSnapshot(t *testing.T) {
	base, err := newFileBlockDevice(&starfile.Bytes{Name: "zero-base", Data: make([]byte, 4096)}, 512, 512, false)
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := newOverlayBlockDevice(base, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := overlay.WriteAt([]byte{7}, 0); err != nil {
		t.Fatal(err)
	}
	snapshot, err := overlay.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := overlay.WriteAt(make([]byte, 4096), 0); err != nil {
		t.Fatal(err)
	}
	value := []byte{0}
	if _, err := snapshot.ReadAt(value, 0); err != nil {
		t.Fatal(err)
	}
	if value[0] != 7 {
		t.Fatalf("snapshot byte = %d, want 7", value[0])
	}
	if got := overlay.dirtyBytes; got != 0 {
		t.Fatalf("live overlay retained %d dirty bytes", got)
	}
}

func TestBlockOverlayStatsExposeDirtyExtentsAndBoundedTrace(t *testing.T) {
	base := testBlockDevice(t, 4*4096)
	overlay, err := newOverlayBlockDevice(base, 4*4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	overlay.traceLimit = 3

	if _, err := overlay.ReadAt(make([]byte, 512), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := overlay.WriteAt([]byte{1}, 4096); err != nil {
		t.Fatal(err)
	}
	if _, err := overlay.ReadAt(make([]byte, 512), 8192); err != nil {
		t.Fatal(err)
	}
	if err := overlay.ZeroAt(12288, 512); err != nil {
		t.Fatal(err)
	}

	stats := overlay.Stats()
	dirty := stats["dirty_extents"].(*starlark.List)
	if dirty.Len() != 2 {
		t.Fatalf("dirty extent count = %d, want 2", dirty.Len())
	}
	for index, wantOffset := range []int64{4096, 12288} {
		extent := dirty.Index(index).(*starvalue.Record)
		offset, _ := starlarkInt64(extent.Get("offset"))
		length, _ := starlarkInt64(extent.Get("length"))
		if offset != wantOffset || length != 4096 {
			t.Fatalf("dirty extent %d = (%d, %d), want (%d, 4096)", index, offset, length, wantOffset)
		}
	}

	recent := stats["recent_operations"].(*starlark.List)
	if recent.Len() != 3 {
		t.Fatalf("recent operation count = %d, want 3", recent.Len())
	}
	want := []struct {
		sequence uint64
		kind     string
		offset   int64
		length   int64
	}{
		{2, "write", 4096, 1},
		{3, "read", 8192, 512},
		{4, "zero", 12288, 512},
	}
	for index, expected := range want {
		operation := recent.Index(index).(*starvalue.Record)
		sequence, _ := operation.Get("sequence").(starlark.Int).Uint64()
		kind := string(operation.Get("kind").(starlark.String))
		offset, _ := starlarkInt64(operation.Get("offset"))
		length, _ := starlarkInt64(operation.Get("length"))
		if sequence != expected.sequence || kind != expected.kind || offset != expected.offset || length != expected.length {
			t.Fatalf("recent operation %d = (%d, %q, %d, %d), want (%d, %q, %d, %d)", index, sequence, kind, offset, length, expected.sequence, expected.kind, expected.offset, expected.length)
		}
	}
}

type countingBlockDevice struct {
	base  BlockDevice
	reads atomic.Uint64
	gate  chan struct{}
}

func (d *countingBlockDevice) ReadAt(p []byte, off int64) (int, error) {
	d.reads.Add(1)
	if d.gate != nil {
		<-d.gate
	}
	return d.base.ReadAt(p, off)
}
func (d *countingBlockDevice) Geometry() BlockGeometry         { return d.base.Geometry() }
func (d *countingBlockDevice) Capabilities() BlockCapabilities { return d.base.Capabilities() }

func TestBlockCacheCoalescesMissesAndEvictsWithinLimit(t *testing.T) {
	base := &countingBlockDevice{base: testBlockDevice(t, 3*4096), gate: make(chan struct{})}
	cache, err := newCachedBlockDevice(base, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}

	const readers = 12
	var ready sync.WaitGroup
	var done sync.WaitGroup
	ready.Add(readers)
	done.Add(readers)
	errs := make(chan error, readers)
	for range readers {
		go func() {
			defer done.Done()
			ready.Done()
			data := make([]byte, 512)
			_, err := cache.ReadAt(data, 0)
			errs <- err
		}()
	}
	ready.Wait()
	deadline := time.Now().Add(time.Second)
	for base.reads.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(base.gate)
	done.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := base.reads.Load(); got != 1 {
		t.Fatalf("coalesced base reads = %d, want 1", got)
	}

	base.gate = nil
	if _, err := cache.ReadAt(make([]byte, 512), 4096); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.ReadAt(make([]byte, 512), 0); err != nil {
		t.Fatal(err)
	}
	if got := base.reads.Load(); got != 3 {
		t.Fatalf("base reads after two evictions = %d, want 3", got)
	}
	stats := cache.Stats()
	if got, _ := starlarkInt64(stats["bytes"]); got > 4096 {
		t.Fatalf("cache retained %d bytes, limit 4096", got)
	}
}

func TestBlockCachePrefetchIsCapabilityDerivedAndBounded(t *testing.T) {
	base := testBlockDevice(t, 1<<20)
	cache, err := newCachedBlockDevice(base, 128<<10, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if !cache.Capabilities().Prefetch {
		t.Fatal("bounded cache did not advertise prefetch")
	}
	if err := cache.Prefetch(0, 256<<10); err != nil {
		t.Fatal(err)
	}
	stats := cache.Stats()
	bytes, _ := starlark.AsInt32(stats["bytes"])
	if bytes > 128<<10 {
		t.Fatalf("prefetch retained %d bytes beyond cache limit", bytes)
	}
	overlay, err := newOverlayBlockDevice(cache, 64<<10, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if !overlay.Capabilities().Prefetch || overlay.Prefetch(512<<10, 64<<10) != nil {
		t.Fatal("snapshot overlay did not propagate cache prefetch")
	}
}

func starlarkInt64(value interface{ String() string }) (int64, bool) {
	integer, ok := value.(interface{ Int64() (int64, bool) })
	if !ok {
		return 0, false
	}
	return integer.Int64()
}

func TestReadFullAtRejectsShortReader(t *testing.T) {
	reader := io.NewSectionReader(&starfile.Bytes{Name: "short", Data: []byte{1, 2}}, 0, 2)
	if _, err := readFullAt(reader, make([]byte, 3), 0); err == nil {
		t.Fatal("short read succeeded")
	}
}

func TestBlockViewExposesLiveReadOnlyFile(t *testing.T) {
	base := testBlockDevice(t, 4096)
	overlay, err := newOverlayBlockDevice(base, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	value, err := blockViewBuiltin(
		&starlark.Thread{Name: "block-view-test"},
		nil,
		starlark.Tuple{NewValue("overlay", overlay)},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	view, ok := value.(starfile.File)
	if !ok {
		t.Fatalf("block.view returned %T, want starfile.File", value)
	}

	before := make([]byte, 4)
	if _, err := view.ReadAt(before, 700); err != nil {
		t.Fatal(err)
	}
	want := []byte("live")
	if _, err := overlay.WriteAt(want, 700); err != nil {
		t.Fatal(err)
	}
	after := make([]byte, len(want))
	if _, err := view.ReadAt(after, 700); err != nil {
		t.Fatal(err)
	}
	if string(after) != string(want) || string(after) == string(before) {
		t.Fatalf("live view read = %q, before = %q, want %q", after, before, want)
	}
	if _, err := view.WriteAt([]byte("no"), 0); !errors.Is(err, ErrBlockReadOnly) {
		t.Fatalf("live view write = %v, want ErrBlockReadOnly", err)
	}

	sliceMethod, err := view.(starlark.HasAttrs).Attr("slice")
	if err != nil {
		t.Fatal(err)
	}
	sliced, err := starlark.Call(
		&starlark.Thread{Name: "block-view-slice-test"},
		sliceMethod.(starlark.Callable),
		starlark.Tuple{starlark.MakeInt(700), starlark.MakeInt(len(want))},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := sliced.(starfile.File).ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("sliced live view read = %q, want %q", got, want)
	}
}
