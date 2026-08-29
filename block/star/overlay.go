package star

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"

	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const (
	defaultBlockOverlayLimit = 128 << 20
	defaultBlockOverlayChunk = 64 << 10
)

const DefaultOverlayChunk = defaultBlockOverlayChunk

// BlockCapacityError reports a bounded overlay refusing additional dirty
// memory. It is intentionally distinct from host allocation failure.
type BlockCapacityError struct {
	Limit     int64
	Allocated int64
	Requested int64
}

func (e *BlockCapacityError) Error() string {
	return fmt.Sprintf("block overlay capacity exceeded: allocated=%d requested=%d limit=%d", e.Allocated, e.Requested, e.Limit)
}

type overlayBlockDevice struct {
	base      BlockDevice
	maxDirty  int64
	chunkSize int64

	mu         sync.RWMutex
	chunks     map[int64]*overlayChunk
	dirtyBytes int64
	generation uint64
	sealed     bool
	leases     int
	reads      atomic.Uint64
	writes     atomic.Uint64
	readBytes  atomic.Uint64
	writeBytes atomic.Uint64
	snapshots  atomic.Uint64
	cowBytes   atomic.Uint64

	traceMu    sync.Mutex
	traceLimit int
	traceNext  uint64
	trace      []blockOverlayOperation
}

type OverlayDevice = overlayBlockDevice

func NewOverlayDevice(base BlockDevice, maxDirty, chunkSize int64) (*OverlayDevice, error) {
	return newOverlayBlockDevice(base, maxDirty, chunkSize)
}

func (d *overlayBlockDevice) Base() BlockDevice { return d.base }

func (d *overlayBlockDevice) LeaseCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.leases
}

type overlayChunk struct {
	data       []byte
	generation uint64
}

type blockOverlayOperation struct {
	sequence uint64
	kind     string
	offset   int64
	length   int64
}

func newOverlayBlockDevice(base BlockDevice, maxDirty, chunkSize int64) (*overlayBlockDevice, error) {
	if maxDirty <= 0 || chunkSize <= 0 {
		return nil, fmt.Errorf("block.overlay: max_dirty_bytes and chunk_size must be positive")
	}
	if chunkSize > maxDirty {
		return nil, fmt.Errorf("block.overlay: chunk_size exceeds max_dirty_bytes")
	}
	if logical := int64(base.Geometry().LogicalBlockSize); chunkSize%logical != 0 {
		return nil, fmt.Errorf("block.overlay: chunk_size must be a multiple of the logical block size")
	}
	return &overlayBlockDevice{
		base:       base,
		maxDirty:   maxDirty,
		chunkSize:  chunkSize,
		chunks:     make(map[int64]*overlayChunk),
		generation: 1,
	}, nil
}

func blockOverlayBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maxDirty := int64(defaultBlockOverlayLimit)
	chunkSize := int64(defaultBlockOverlayChunk)
	traceOperations := 0
	if err := starlark.UnpackArgs("overlay", args, kwargs,
		"base", &value,
		"max_dirty_bytes?", &maxDirty,
		"chunk_size?", &chunkSize,
		"trace_operations?", &traceOperations,
	); err != nil {
		return nil, err
	}
	base, err := AsDevice(value)
	if err != nil {
		return nil, fmt.Errorf("overlay: base: %w", err)
	}
	overlay, err := newOverlayBlockDevice(base, maxDirty, chunkSize)
	if err != nil {
		return nil, err
	}
	if traceOperations < 0 || traceOperations > 65536 {
		return nil, fmt.Errorf("overlay: trace_operations must be between 0 and 65536")
	}
	overlay.traceLimit = traceOperations
	return NewValue("overlay", overlay), nil
}

func (d *overlayBlockDevice) Geometry() BlockGeometry { return d.base.Geometry() }

func (d *overlayBlockDevice) Capabilities() BlockCapabilities {
	return BlockCapabilities{
		Writable:   true,
		Flush:      true,
		Zero:       true,
		Extents:    true,
		Concurrent: true,
		Durable:    false,
		Prefetch:   d.base.Capabilities().Prefetch,
	}
}

func (d *overlayBlockDevice) Prefetch(off, length int64) error {
	prefetcher, ok := d.base.(blockDevicePrefetcher)
	if !ok || !d.base.Capabilities().Prefetch {
		return ErrBlockUnsupported
	}
	return prefetcher.Prefetch(off, length)
}

func (d *overlayBlockDevice) Extents(off, length int64) ([]BlockExtent, error) {
	if err := validateBlockRange(d.Geometry().Size, off, length); err != nil {
		return nil, err
	}
	d.mu.RLock()
	dirty := make(map[int64]struct{}, len(d.chunks))
	for index := range d.chunks {
		dirty[index] = struct{}{}
	}
	d.mu.RUnlock()
	return overlayExtentMap(d.base, dirty, d.chunkSize, off, length)
}

func (d *overlayBlockDevice) ReadAt(p []byte, off int64) (int, error) {
	if err := validateBlockRange(d.Geometry().Size, off, int64(len(p))); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	done := 0
	for done < len(p) {
		absolute := off + int64(done)
		index := absolute / d.chunkSize
		within := absolute % d.chunkSize
		length := d.chunkLength(index)
		count := int64(len(p) - done)
		if available := length - within; count > available {
			count = available
		}
		if count <= 0 {
			return done, io.ErrUnexpectedEOF
		}
		if chunk, ok := d.chunks[index]; ok {
			copy(p[done:done+int(count)], chunk.data[within:within+count])
		} else if _, err := readFullAt(d.base, p[done:done+int(count)], absolute); err != nil {
			return done, err
		}
		done += int(count)
	}
	d.reads.Add(1)
	d.readBytes.Add(uint64(done))
	d.recordOperation("read", off, int64(done))
	return done, nil
}

func (d *overlayBlockDevice) WriteAt(p []byte, off int64) (int, error) {
	if err := validateBlockRange(d.Geometry().Size, off, int64(len(p))); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sealed {
		return 0, ErrBlockReadOnly
	}

	if err := d.updateLocked(off, int64(len(p)), p, false); err != nil {
		return 0, err
	}
	d.writes.Add(1)
	d.writeBytes.Add(uint64(len(p)))
	d.recordOperation("write", off, int64(len(p)))
	return len(p), nil
}

// updateLocked stages a complete range before committing it. Chunks equal to
// the lazy base are omitted, which keeps guest zero-initialization and rewrites
// of unchanged sectors from consuming overlay capacity.
func (d *overlayBlockDevice) updateLocked(off, length int64, data []byte, zero bool) error {
	type update struct {
		chunk  *overlayChunk
		cloned bool
	}
	updates := make(map[int64]update)
	dirtyBytes := d.dirtyBytes
	end := off + length
	for index := off / d.chunkSize; index <= (end-1)/d.chunkSize; index++ {
		chunkStart := index * d.chunkSize
		chunkLength := d.chunkLength(index)
		current, existed := d.chunks[index]
		candidate := make([]byte, chunkLength)
		var base []byte
		cloned := false
		if existed {
			copy(candidate, current.data)
			cloned = current.generation != d.generation
		} else {
			base = make([]byte, chunkLength)
			if _, err := readFullAt(d.base, base, chunkStart); err != nil {
				return err
			}
			copy(candidate, base)
		}
		start := max(off, chunkStart)
		finish := min(end, chunkStart+chunkLength)
		within := start - chunkStart
		count := finish - start
		if zero {
			clear(candidate[within : within+count])
		} else {
			source := start - off
			copy(candidate[within:within+count], data[source:source+count])
		}
		if !existed || count == chunkLength {
			if base == nil {
				base = make([]byte, chunkLength)
				if _, err := readFullAt(d.base, base, chunkStart); err != nil {
					return err
				}
			}
			if bytes.Equal(candidate, base) {
				updates[index] = update{}
				if existed {
					dirtyBytes -= chunkLength
				}
				continue
			}
		}
		updates[index] = update{chunk: &overlayChunk{data: candidate, generation: d.generation}, cloned: cloned}
		if !existed {
			dirtyBytes += chunkLength
		}
	}
	if dirtyBytes > d.maxDirty {
		return &BlockCapacityError{Limit: d.maxDirty, Allocated: d.dirtyBytes, Requested: dirtyBytes - d.dirtyBytes}
	}
	for index, update := range updates {
		if update.chunk == nil {
			delete(d.chunks, index)
			continue
		}
		d.chunks[index] = update.chunk
		if update.cloned {
			d.cowBytes.Add(uint64(len(update.chunk.data)))
		}
	}
	d.dirtyBytes = dirtyBytes
	return nil
}

func (d *overlayBlockDevice) Flush() error { return nil }

func (d *overlayBlockDevice) ZeroAt(off, length int64) error {
	if err := validateBlockRange(d.Geometry().Size, off, length); err != nil {
		return err
	}
	if length == 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sealed {
		return ErrBlockReadOnly
	}
	if err := d.updateLocked(off, length, nil, true); err != nil {
		return err
	}
	d.writes.Add(1)
	d.writeBytes.Add(uint64(length))
	d.recordOperation("zero", off, length)
	return nil
}

func (d *overlayBlockDevice) recordOperation(kind string, offset, length int64) {
	if d.traceLimit == 0 {
		return
	}
	d.traceMu.Lock()
	d.traceNext++
	operation := blockOverlayOperation{sequence: d.traceNext, kind: kind, offset: offset, length: length}
	if len(d.trace) < d.traceLimit {
		d.trace = append(d.trace, operation)
	} else {
		copy(d.trace, d.trace[1:])
		d.trace[len(d.trace)-1] = operation
	}
	d.traceMu.Unlock()
}

func (d *overlayBlockDevice) Acquire() (func(), error) {
	d.mu.Lock()
	if d.sealed {
		d.mu.Unlock()
		return nil, fmt.Errorf("block overlay is sealed")
	}
	d.leases++
	d.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			d.mu.Lock()
			d.leases--
			d.mu.Unlock()
		})
	}, nil
}

func (d *overlayBlockDevice) Commit() (starfile.File, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.leases != 0 {
		return nil, fmt.Errorf("block overlay has %d active lease(s)", d.leases)
	}
	d.sealed = true
	return &blockDeviceFile{name: "block overlay", device: d}, nil
}

func (d *overlayBlockDevice) Snapshot() (starfile.File, error) {
	d.mu.Lock()
	if d.sealed {
		d.mu.Unlock()
		return nil, fmt.Errorf("block overlay is sealed")
	}
	chunks := make(map[int64][]byte, len(d.chunks))
	for index, chunk := range d.chunks {
		chunks[index] = chunk.data
	}
	d.generation++
	snapshot := &overlaySnapshotBlockDevice{base: d.base, chunkSize: d.chunkSize, chunks: chunks}
	d.mu.Unlock()
	d.snapshots.Add(1)
	return &blockDeviceFile{name: "block overlay snapshot", device: snapshot}, nil
}

func (d *overlayBlockDevice) Stats() starlark.StringDict {
	d.mu.RLock()
	dirtyBytes, chunks, leases, sealed := d.dirtyBytes, len(d.chunks), d.leases, d.sealed
	indices := make([]int64, 0, len(d.chunks))
	for index := range d.chunks {
		indices = append(indices, index)
	}
	d.mu.RUnlock()
	d.traceMu.Lock()
	operations := append([]blockOverlayOperation(nil), d.trace...)
	d.traceMu.Unlock()
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })
	dirtyExtents := make([]starlark.Value, 0, len(indices))
	for first := 0; first < len(indices); {
		last := first + 1
		for last < len(indices) && indices[last] == indices[last-1]+1 {
			last++
		}
		offset := indices[first] * d.chunkSize
		length := int64(last-first) * d.chunkSize
		if offset+length > d.Geometry().Size {
			length = d.Geometry().Size - offset
		}
		dirtyExtents = append(dirtyExtents, starvalue.NewRecord(starlark.StringDict{
			"offset": starlark.MakeInt64(offset),
			"length": starlark.MakeInt64(length),
		}))
		first = last
	}
	recentOperations := make([]starlark.Value, 0, len(operations))
	for _, operation := range operations {
		recentOperations = append(recentOperations, starvalue.NewRecord(starlark.StringDict{
			"sequence": starlark.MakeUint64(operation.sequence),
			"kind":     starlark.String(operation.kind),
			"offset":   starlark.MakeInt64(operation.offset),
			"length":   starlark.MakeInt64(operation.length),
		}))
	}
	return starlark.StringDict{
		"chunks":              starlark.MakeInt(chunks),
		"copy_on_write_bytes": starlark.MakeUint64(d.cowBytes.Load()),
		"dirty_bytes":         starlark.MakeInt64(dirtyBytes),
		"dirty_extents":       starlark.NewList(dirtyExtents),
		"leases":              starlark.MakeInt(leases),
		"max_dirty_bytes":     starlark.MakeInt64(d.maxDirty),
		"read_bytes":          starlark.MakeUint64(d.readBytes.Load()),
		"reads":               starlark.MakeUint64(d.reads.Load()),
		"recent_operations":   starlark.NewList(recentOperations),
		"sealed":              starlark.Bool(sealed),
		"snapshots":           starlark.MakeUint64(d.snapshots.Load()),
		"write_bytes":         starlark.MakeUint64(d.writeBytes.Load()),
		"writes":              starlark.MakeUint64(d.writes.Load()),
	}
}

type overlaySnapshotBlockDevice struct {
	base      BlockDevice
	chunkSize int64
	chunks    map[int64][]byte
}

func (d *overlaySnapshotBlockDevice) Geometry() BlockGeometry { return d.base.Geometry() }
func (d *overlaySnapshotBlockDevice) Capabilities() BlockCapabilities {
	return BlockCapabilities{Extents: true, Concurrent: true}
}
func (d *overlaySnapshotBlockDevice) ReadAt(p []byte, off int64) (int, error) {
	if err := validateBlockRange(d.Geometry().Size, off, int64(len(p))); err != nil {
		return 0, err
	}
	done := 0
	for done < len(p) {
		absolute := off + int64(done)
		index := absolute / d.chunkSize
		within := absolute % d.chunkSize
		length := d.chunkSize
		if remaining := d.Geometry().Size - index*d.chunkSize; remaining < length {
			length = remaining
		}
		count := int64(len(p) - done)
		if available := length - within; count > available {
			count = available
		}
		if chunk, ok := d.chunks[index]; ok {
			copy(p[done:done+int(count)], chunk[within:within+count])
		} else if _, err := readFullAt(d.base, p[done:done+int(count)], absolute); err != nil {
			return done, err
		}
		done += int(count)
	}
	return done, nil
}
func (d *overlaySnapshotBlockDevice) Extents(off, length int64) ([]BlockExtent, error) {
	if err := validateBlockRange(d.Geometry().Size, off, length); err != nil {
		return nil, err
	}
	dirty := make(map[int64]struct{}, len(d.chunks))
	for index := range d.chunks {
		dirty[index] = struct{}{}
	}
	return overlayExtentMap(d.base, dirty, d.chunkSize, off, length)
}

func overlayExtentMap(base BlockDevice, dirty map[int64]struct{}, chunkSize, off, length int64) ([]BlockExtent, error) {
	if length == 0 {
		return nil, nil
	}
	end := off + length
	indices := make([]int64, 0, len(dirty))
	for index := range dirty {
		chunkStart := index * chunkSize
		if chunkStart < end && chunkStart+chunkSize > off {
			indices = append(indices, index)
		}
	}
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })
	out := make([]BlockExtent, 0, len(indices)*2+1)
	appendExtent := func(extent BlockExtent) {
		if extent.Length <= 0 {
			return
		}
		if len(out) > 0 {
			last := &out[len(out)-1]
			if last.Offset+last.Length == extent.Offset && last.Allocated == extent.Allocated {
				last.Length += extent.Length
				return
			}
		}
		out = append(out, extent)
	}
	appendBase := func(start, size int64) error {
		if size <= 0 {
			return nil
		}
		provider, ok := base.(blockDeviceExtenter)
		if !ok || !base.Capabilities().Extents {
			appendExtent(BlockExtent{Offset: start, Length: size, Allocated: true})
			return nil
		}
		extents, err := provider.Extents(start, size)
		if err != nil {
			return err
		}
		expected := start
		for _, extent := range extents {
			if extent.Offset != expected || extent.Length <= 0 || extent.Length > start+size-expected {
				return fmt.Errorf("block overlay: base extent map does not cover requested range")
			}
			appendExtent(extent)
			expected += extent.Length
		}
		if expected != start+size {
			return fmt.Errorf("block overlay: base extent map does not cover requested range")
		}
		return nil
	}
	position := off
	for _, index := range indices {
		chunkStart := index * chunkSize
		chunkEnd := min(end, chunkStart+chunkSize)
		if position < chunkStart {
			if err := appendBase(position, chunkStart-position); err != nil {
				return nil, err
			}
			position = chunkStart
		}
		if position < chunkEnd {
			appendExtent(BlockExtent{Offset: position, Length: chunkEnd - position, Allocated: true})
			position = chunkEnd
		}
	}
	if position < end {
		if err := appendBase(position, end-position); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (d *overlayBlockDevice) chunkLength(index int64) int64 {
	off := index * d.chunkSize
	length := d.chunkSize
	if remaining := d.Geometry().Size - off; remaining < length {
		length = remaining
	}
	return length
}
