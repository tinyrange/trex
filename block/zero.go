package block

import "fmt"

// ZeroDevice is immutable unallocated storage with real zero-valued bytes.
// Its size does not cause an allocation; it is suitable as an overlay base.
type ZeroDevice struct{ geometry Geometry }

func NewZeroDevice(size int64, sector uint32) (*ZeroDevice, error) {
	if err := validateBlockSize("logical block size", sector); err != nil {
		return nil, err
	}
	if size < 0 || size%int64(sector) != 0 {
		return nil, fmt.Errorf("block: zero storage requires complete sectors")
	}
	return &ZeroDevice{Geometry{Size: size, LogicalBlockSize: sector, PhysicalBlockSize: sector, MinimumTransfer: sector, PreferredTransfer: DefaultTransferSize, MaximumTransfer: DefaultMaxTransferSize}}, nil
}
func (d *ZeroDevice) ReadAt(p []byte, off int64) (int, error) {
	if err := ValidateRange(d.geometry.Size, off, int64(len(p))); err != nil {
		return 0, err
	}
	clear(p)
	return len(p), nil
}
func (d *ZeroDevice) Geometry() Geometry { return d.geometry }
func (d *ZeroDevice) Capabilities() Capabilities {
	return Capabilities{Concurrent: true, Extents: true}
}
func (d *ZeroDevice) Extents(off, length int64) ([]Extent, error) {
	if err := ValidateRange(d.geometry.Size, off, length); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	return []Extent{{Offset: off, Length: length}}, nil
}
