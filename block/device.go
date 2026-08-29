// Package block defines transport-neutral random-access block devices.
package block

import (
	"errors"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

const (
	DefaultBlockSize       = 512
	DefaultTransferSize    = 64 << 10
	DefaultMaxTransferSize = 8 << 20
)

var (
	ErrReadOnly    = errors.New("block device is read-only")
	ErrUnsupported = errors.New("block operation is unsupported")
	ErrOutOfRange  = errors.New("block range is out of bounds")
)

type Geometry struct {
	Size              int64
	LogicalBlockSize  uint32
	PhysicalBlockSize uint32
	MinimumTransfer   uint32
	PreferredTransfer uint32
	MaximumTransfer   uint32
}

type Capabilities struct {
	Writable   bool
	Flush      bool
	Zero       bool
	Trim       bool
	Extents    bool
	Concurrent bool
	Durable    bool
	Prefetch   bool
}

type Extent struct {
	Offset    int64
	Length    int64
	Allocated bool
}

type Device interface {
	ReadAt([]byte, int64) (int, error)
	Geometry() Geometry
	Capabilities() Capabilities
}

type Writer interface {
	WriteAt([]byte, int64) (int, error)
}
type Flusher interface{ Flush() error }
type Zeroer interface{ ZeroAt(int64, int64) error }
type Trimmer interface{ TrimAt(int64, int64) error }
type Extenter interface {
	Extents(int64, int64) ([]Extent, error)
}
type Prefetcher interface{ Prefetch(int64, int64) error }

type FileDeviceOptions struct {
	LogicalBlockSize  uint32
	PhysicalBlockSize uint32
	Writable          bool
}

type FileDevice struct {
	file      storage.Reader
	geometry  Geometry
	writable  bool
	flushable bool
}

func NewFileDevice(file storage.Reader, options FileDeviceOptions) (*FileDevice, error) {
	if file == nil {
		return nil, fmt.Errorf("block: nil file")
	}
	logical := options.LogicalBlockSize
	if logical == 0 {
		logical = DefaultBlockSize
	}
	physical := options.PhysicalBlockSize
	if physical == 0 {
		physical = logical
	}
	if err := validateBlockSize("logical block size", logical); err != nil {
		return nil, err
	}
	if err := validateBlockSize("physical block size", physical); err != nil {
		return nil, err
	}
	if physical < logical || physical%logical != 0 {
		return nil, fmt.Errorf("block: physical block size must be a multiple of logical block size")
	}
	if file.Size() < 0 {
		return nil, fmt.Errorf("block: file has negative size")
	}
	if options.Writable {
		if _, ok := file.(io.WriterAt); !ok {
			return nil, fmt.Errorf("block: writable file does not implement io.WriterAt")
		}
	}
	_, flushable := file.(interface{ Sync() error })
	return &FileDevice{
		file: file, writable: options.Writable, flushable: flushable,
		geometry: Geometry{
			Size: file.Size(), LogicalBlockSize: logical, PhysicalBlockSize: physical,
			MinimumTransfer: DefaultBlockSize, PreferredTransfer: DefaultTransferSize,
			MaximumTransfer: DefaultMaxTransferSize,
		},
	}, nil
}

func (d *FileDevice) ReadAt(p []byte, off int64) (int, error) {
	if err := ValidateRange(d.geometry.Size, off, int64(len(p))); err != nil {
		return 0, err
	}
	return ReadFullAt(d.file, p, off)
}

func (d *FileDevice) WriteAt(p []byte, off int64) (int, error) {
	if !d.writable {
		return 0, ErrReadOnly
	}
	if err := ValidateRange(d.geometry.Size, off, int64(len(p))); err != nil {
		return 0, err
	}
	n, err := d.file.(io.WriterAt).WriteAt(p, off)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (d *FileDevice) Flush() error {
	if !d.writable {
		return ErrReadOnly
	}
	syncer, ok := d.file.(interface{ Sync() error })
	if !ok {
		return ErrUnsupported
	}
	return syncer.Sync()
}

func (d *FileDevice) ZeroAt(off, length int64) error {
	if !d.writable {
		return ErrReadOnly
	}
	if err := ValidateRange(d.geometry.Size, off, length); err != nil {
		return err
	}
	zeroes := make([]byte, 128<<10)
	for length > 0 {
		chunk := min(int64(len(zeroes)), length)
		n, err := d.WriteAt(zeroes[:chunk], off)
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

func (d *FileDevice) Extents(off, length int64) ([]Extent, error) {
	if err := ValidateRange(d.geometry.Size, off, length); err != nil {
		return nil, err
	}
	if provider, ok := d.file.(interface {
		Extents(int64, int64) ([]Extent, error)
	}); ok {
		return provider.Extents(off, length)
	}
	return []Extent{{Offset: off, Length: length, Allocated: true}}, nil
}

func (d *FileDevice) Geometry() Geometry { return d.geometry }

func (d *FileDevice) Capabilities() Capabilities {
	_, extents := d.file.(interface {
		Extents(int64, int64) ([]Extent, error)
	})
	return Capabilities{
		Writable: d.writable, Flush: d.writable && d.flushable, Zero: d.writable,
		Extents: extents, Concurrent: true, Durable: d.writable && d.flushable,
	}
}

func ValidateRange(size, off, length int64) error {
	if size < 0 || off < 0 || length < 0 || off > size || length > size-off {
		return ErrOutOfRange
	}
	return nil
}

func ReadFullAt(reader io.ReaderAt, p []byte, off int64) (int, error) {
	done := 0
	for done < len(p) {
		n, err := reader.ReadAt(p[done:], off+int64(done))
		done += n
		if err != nil {
			if err == io.EOF && done == len(p) {
				return done, nil
			}
			return done, err
		}
		if n == 0 {
			return done, io.ErrUnexpectedEOF
		}
	}
	return done, nil
}

func validateBlockSize(name string, size uint32) error {
	if size == 0 || size&(size-1) != 0 {
		return fmt.Errorf("block: %s must be a non-zero power of two", name)
	}
	return nil
}
