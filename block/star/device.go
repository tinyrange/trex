package star

import (
	"fmt"
	"io"
	"math"
	"strings"

	blockpkg "github.com/tinyrange/trex/block"
	starvalue "github.com/tinyrange/trex/script/value"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const (
	defaultBlockSize         = 512
	defaultBlockTransfer     = 64 << 10
	defaultBlockMaxTransfer  = 8 << 20
	defaultBlockBuiltinLimit = 64 << 20
)

var (
	ErrBlockReadOnly    = blockpkg.ErrReadOnly
	ErrBlockUnsupported = blockpkg.ErrUnsupported
	ErrBlockOutOfRange  = blockpkg.ErrOutOfRange
)

type BlockGeometry = blockpkg.Geometry
type BlockCapabilities = blockpkg.Capabilities
type BlockExtent = blockpkg.Extent
type BlockDevice = blockpkg.Device
type BlockDeviceWriter = blockpkg.Writer
type BlockDeviceFlusher = blockpkg.Flusher
type BlockDeviceZeroer = blockpkg.Zeroer
type BlockDeviceTrimmer = blockpkg.Trimmer
type BlockDeviceExtenter = blockpkg.Extenter
type BlockDevicePrefetcher = blockpkg.Prefetcher

type blockDeviceWriter = BlockDeviceWriter
type blockDeviceFlusher = BlockDeviceFlusher
type blockDeviceZeroer = BlockDeviceZeroer
type blockDeviceTrimmer = BlockDeviceTrimmer
type blockDeviceExtenter = BlockDeviceExtenter
type blockDevicePrefetcher = BlockDevicePrefetcher

type blockDeviceCommitter interface {
	Commit() (starfile.File, error)
}

type blockDeviceSnapshotter interface {
	Snapshot() (starfile.File, error)
}

type blockDeviceStats interface {
	Stats() starlark.StringDict
}

type blockDeviceLease interface {
	Acquire() (func(), error)
}

func Builtins() starlark.StringDict {
	return starlark.StringDict{
		"cache":   starlark.NewBuiltin("cache", blockCacheBuiltin),
		"device":  starlark.NewBuiltin("device", blockDeviceBuiltin),
		"overlay": starlark.NewBuiltin("overlay", blockOverlayBuiltin),
		"view":    starlark.NewBuiltin("view", blockViewBuiltin),
	}
}

type fileBlockDevice = blockpkg.FileDevice
type FileBlockDeviceOptions = blockpkg.FileDeviceOptions

func NewFileBlockDevice(file storage.Reader, options FileBlockDeviceOptions) (BlockDevice, error) {
	return blockpkg.NewFileDevice(file, options)
}

func newFileBlockDevice(file storage.Reader, logicalBlockSize, physicalBlockSize uint32, writable bool) (*fileBlockDevice, error) {
	return blockpkg.NewFileDevice(file, blockpkg.FileDeviceOptions{LogicalBlockSize: logicalBlockSize, PhysicalBlockSize: physicalBlockSize, Writable: writable})
}

func blockDeviceBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	format := "raw"
	logicalBlockSize := defaultBlockSize
	physicalBlockSize := 0
	writable := false
	if err := starlark.UnpackArgs("device", args, kwargs,
		"file", &value,
		"format?", &format,
		"logical_block_size?", &logicalBlockSize,
		"physical_block_size?", &physicalBlockSize,
		"writable?", &writable,
	); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("device: got %s, want file", value.Type())
	}
	if strings.ToLower(format) != "raw" {
		return nil, fmt.Errorf("device: unsupported format %q; decode it with a trex format implementation first", format)
	}
	if logicalBlockSize <= 0 || logicalBlockSize > math.MaxUint32 || physicalBlockSize < 0 || physicalBlockSize > math.MaxUint32 {
		return nil, fmt.Errorf("device: invalid block size")
	}
	device, err := newFileBlockDevice(file, uint32(logicalBlockSize), uint32(physicalBlockSize), writable)
	if err != nil {
		return nil, err
	}
	return NewValue("file", device), nil
}

type Value struct {
	name   string
	device BlockDevice
}

func (v *Value) Device() BlockDevice { return v.device }

func NewValue(name string, device BlockDevice) *Value {
	return &Value{name: name, device: device}
}

func AsDevice(value starlark.Value) (BlockDevice, error) {
	device, ok := value.(*Value)
	if !ok {
		return nil, fmt.Errorf("got %s, want block_device", value.Type())
	}
	return device.device, nil
}

func blockViewBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("view", args, kwargs, "device", &value); err != nil {
		return nil, err
	}
	device, err := AsDevice(value)
	if err != nil {
		return nil, fmt.Errorf("view: device: %w", err)
	}
	return &blockDeviceFile{name: "block device view", device: device}, nil
}

func (v *Value) String() string {
	return fmt.Sprintf("<block_device %s size=%d>", v.name, v.device.Geometry().Size)
}
func (v *Value) Type() string         { return "block_device" }
func (v *Value) Freeze()              {}
func (v *Value) Truth() starlark.Bool { return starlark.True }
func (v *Value) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", v.Type())
}

func (v *Value) Attr(name string) (starlark.Value, error) {
	switch name {
	case "size":
		return starlark.MakeInt64(v.device.Geometry().Size), nil
	case "geometry":
		return blockGeometryValue(v.device.Geometry()), nil
	case "capabilities":
		return blockCapabilitiesValue(v.device.Capabilities()), nil
	case "read":
		return starlark.NewBuiltin("read", v.readBuiltin), nil
	case "write":
		if v.device.Capabilities().Writable {
			return starlark.NewBuiltin("write", v.writeBuiltin), nil
		}
	case "flush":
		if v.device.Capabilities().Flush {
			return starlark.NewBuiltin("flush", v.flushBuiltin), nil
		}
	case "zero":
		if v.device.Capabilities().Zero {
			return starlark.NewBuiltin("zero", v.zeroBuiltin), nil
		}
	case "trim":
		if v.device.Capabilities().Trim {
			return starlark.NewBuiltin("trim", v.trimBuiltin), nil
		}
	case "extents":
		if v.device.Capabilities().Extents {
			return starlark.NewBuiltin("extents", v.extentsBuiltin), nil
		}
	case "commit":
		if _, ok := v.device.(blockDeviceCommitter); ok {
			return starlark.NewBuiltin("commit", v.commitBuiltin), nil
		}
	case "snapshot":
		if _, ok := v.device.(blockDeviceSnapshotter); ok {
			return starlark.NewBuiltin("snapshot", v.snapshotBuiltin), nil
		}
	case "stats":
		if stats, ok := v.device.(blockDeviceStats); ok {
			return starvalue.NewRecord(stats.Stats()), nil
		}
	}
	return nil, nil
}

func (v *Value) AttrNames() []string {
	names := []string{"capabilities", "geometry", "read", "size"}
	capabilities := v.device.Capabilities()
	if capabilities.Writable {
		names = append(names, "write")
	}
	if capabilities.Flush {
		names = append(names, "flush")
	}
	if capabilities.Zero {
		names = append(names, "zero")
	}
	if capabilities.Trim {
		names = append(names, "trim")
	}
	if capabilities.Extents {
		names = append(names, "extents")
	}
	if _, ok := v.device.(blockDeviceCommitter); ok {
		names = append(names, "commit")
	}
	if _, ok := v.device.(blockDeviceSnapshotter); ok {
		names = append(names, "snapshot")
	}
	if _, ok := v.device.(blockDeviceStats); ok {
		names = append(names, "stats")
	}
	return names
}

func (v *Value) readBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var off int64
	var size int
	if err := starlark.UnpackArgs("read", args, kwargs, "offset", &off, "size", &size); err != nil {
		return nil, err
	}
	if size < 0 || size > defaultBlockBuiltinLimit {
		return nil, fmt.Errorf("read: size must be between 0 and %d", defaultBlockBuiltinLimit)
	}
	data := make([]byte, size)
	if _, err := v.device.ReadAt(data, off); err != nil {
		return nil, err
	}
	return starlark.Bytes(data), nil
}

func (v *Value) writeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var off int64
	var value starlark.Value
	if err := starlark.UnpackArgs("write", args, kwargs, "offset", &off, "value", &value); err != nil {
		return nil, err
	}
	data, err := starfile.BytesForValue(value, defaultBlockBuiltinLimit)
	if err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	writer, ok := v.device.(blockDeviceWriter)
	if !ok || !v.device.Capabilities().Writable {
		return nil, ErrBlockReadOnly
	}
	if _, err := writer.WriteAt(data, off); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

func (v *Value) flushBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("flush", args, kwargs); err != nil {
		return nil, err
	}
	flusher, ok := v.device.(blockDeviceFlusher)
	if !ok {
		return nil, ErrBlockUnsupported
	}
	if err := flusher.Flush(); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

func (v *Value) zeroBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	off, length, err := unpackBlockRange("zero", args, kwargs)
	if err != nil {
		return nil, err
	}
	zeroer, ok := v.device.(blockDeviceZeroer)
	if !ok {
		return nil, ErrBlockUnsupported
	}
	if err := zeroer.ZeroAt(off, length); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

func (v *Value) trimBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	off, length, err := unpackBlockRange("trim", args, kwargs)
	if err != nil {
		return nil, err
	}
	trimmer, ok := v.device.(blockDeviceTrimmer)
	if !ok {
		return nil, ErrBlockUnsupported
	}
	if err := trimmer.TrimAt(off, length); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

func (v *Value) extentsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	off, length, err := unpackBlockRange("extents", args, kwargs)
	if err != nil {
		return nil, err
	}
	extenter, ok := v.device.(blockDeviceExtenter)
	if !ok {
		return nil, ErrBlockUnsupported
	}
	extents, err := extenter.Extents(off, length)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(extents))
	for index, extent := range extents {
		values[index] = starvalue.NewRecord(starlark.StringDict{
			"allocated": starlark.Bool(extent.Allocated),
			"length":    starlark.MakeInt64(extent.Length),
			"offset":    starlark.MakeInt64(extent.Offset),
		})
	}
	return starlark.NewList(values), nil
}

func (v *Value) commitBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("commit", args, kwargs); err != nil {
		return nil, err
	}
	committer, ok := v.device.(blockDeviceCommitter)
	if !ok {
		return nil, ErrBlockUnsupported
	}
	return committer.Commit()
}

func (v *Value) snapshotBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("snapshot", args, kwargs); err != nil {
		return nil, err
	}
	snapshotter, ok := v.device.(blockDeviceSnapshotter)
	if !ok {
		return nil, ErrBlockUnsupported
	}
	return snapshotter.Snapshot()
}

func unpackBlockRange(name string, args starlark.Tuple, kwargs []starlark.Tuple) (int64, int64, error) {
	var off, length int64
	if err := starlark.UnpackArgs(name, args, kwargs, "offset", &off, "length", &length); err != nil {
		return 0, 0, err
	}
	if off < 0 || length < 0 {
		return 0, 0, fmt.Errorf("%s: offset and length must be non-negative", name)
	}
	return off, length, nil
}

func blockGeometryValue(geometry BlockGeometry) starlark.Value {
	return starvalue.NewRecord(starlark.StringDict{
		"logical_block_size":  starlark.MakeUint64(uint64(geometry.LogicalBlockSize)),
		"maximum_transfer":    starlark.MakeUint64(uint64(geometry.MaximumTransfer)),
		"minimum_transfer":    starlark.MakeUint64(uint64(geometry.MinimumTransfer)),
		"physical_block_size": starlark.MakeUint64(uint64(geometry.PhysicalBlockSize)),
		"preferred_transfer":  starlark.MakeUint64(uint64(geometry.PreferredTransfer)),
		"size":                starlark.MakeInt64(geometry.Size),
	})
}

func blockCapabilitiesValue(capabilities BlockCapabilities) starlark.Value {
	return starvalue.NewRecord(starlark.StringDict{
		"concurrent": starlark.Bool(capabilities.Concurrent),
		"durable":    starlark.Bool(capabilities.Durable),
		"prefetch":   starlark.Bool(capabilities.Prefetch),
		"extents":    starlark.Bool(capabilities.Extents),
		"flush":      starlark.Bool(capabilities.Flush),
		"trim":       starlark.Bool(capabilities.Trim),
		"writable":   starlark.Bool(capabilities.Writable),
		"zero":       starlark.Bool(capabilities.Zero),
	})
}

func validateBlockSize(name string, size uint32) error {
	if size == 0 || size&(size-1) != 0 {
		return fmt.Errorf("block.device: %s must be a non-zero power of two", name)
	}
	return nil
}

func validateBlockRange(size, off, length int64) error {
	return blockpkg.ValidateRange(size, off, length)
}

func readFullAt(reader io.ReaderAt, p []byte, off int64) (int, error) {
	return blockpkg.ReadFullAt(reader, p, off)
}

func writeBlockZeroes(writer blockDeviceWriter, off, length int64) error {
	if length < 0 || off < 0 {
		return ErrBlockOutOfRange
	}
	zeroes := make([]byte, 128<<10)
	for length > 0 {
		chunk := int64(len(zeroes))
		if length < chunk {
			chunk = length
		}
		n, err := writer.WriteAt(zeroes[:chunk], off)
		if err != nil {
			return err
		}
		if int64(n) != chunk {
			return io.ErrShortWrite
		}
		off += chunk
		length -= chunk
	}
	return nil
}

type blockDeviceFile struct {
	name   string
	device BlockDevice
}

func (f *blockDeviceFile) ReadAt(p []byte, off int64) (int, error) {
	return f.device.ReadAt(p, off)
}
func (f *blockDeviceFile) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, ErrBlockReadOnly
}
func (f *blockDeviceFile) Size() int64           { return f.device.Geometry().Size }
func (f *blockDeviceFile) String() string        { return fmt.Sprintf("<file %q>", f.name) }
func (f *blockDeviceFile) Type() string          { return "file" }
func (f *blockDeviceFile) Freeze()               {}
func (f *blockDeviceFile) Truth() starlark.Bool  { return starlark.True }
func (f *blockDeviceFile) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", f.Type()) }
func (f *blockDeviceFile) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *blockDeviceFile) AttrNames() []string { return starfile.AttrNames() }
