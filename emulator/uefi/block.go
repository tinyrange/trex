package uefi

import (
	"fmt"

	"github.com/tinyrange/trex/block"
	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/storage"
)

const blockIOGUID = "{964E5B21-6459-11D2-8E39-00A0C969723B}"
const diskIOGUID = "{CE345171-BA0B-11D2-8E4F-00A0C969723B}"

type BlockOptions struct {
	DevicePath   []byte
	Handle       uint64
	ReadOnly     bool
	BlockSize    uint32
	OverlayBytes int64
}
type diskStore struct {
	overlay *blockstar.OverlayDevice
	limit   int64
}
type blockEndpoint struct {
	Store        int
	Offset, Size int64
	BlockSize    uint32
	ReadOnly     bool
	Handle       uint64
}

// AttachBlockDevice gives firmware a private in-memory overlay over a stable
// byte source. It never writes to the source or materializes an image on disk.
func (m *Machine) AttachBlockDevice(source storage.Reader, opts BlockOptions) (uint64, error) {
	if opts.BlockSize == 0 {
		opts.BlockSize = 512
	}
	if opts.OverlayBytes == 0 {
		opts.OverlayBytes = 128 << 20
	}
	base, err := block.NewFileDevice(source, block.FileDeviceOptions{LogicalBlockSize: opts.BlockSize})
	if err != nil {
		return 0, err
	}
	if source.Size() == 0 || source.Size()%int64(opts.BlockSize) != 0 {
		return 0, fmt.Errorf("uefi: block device must contain whole blocks")
	}
	overlay, err := blockstar.NewOverlayDevice(base, opts.OverlayBytes, 64<<10)
	if err != nil {
		return 0, err
	}
	index := len(m.diskStores)
	m.diskStores = append(m.diskStores, diskStore{overlay, opts.OverlayBytes})
	return m.attachEndpoint(blockEndpoint{Store: index, Size: source.Size(), BlockSize: opts.BlockSize, ReadOnly: opts.ReadOnly}, opts.Handle, opts.DevicePath, false)
}

// AttachBlockPartition shares the parent's overlay, so reads through whole-disk
// and partition handles observe exactly the same bytes and checkpoint state.
func (m *Machine) AttachBlockPartition(parent uint64, offset, size int64, devicePath []byte, handle uint64) (uint64, error) {
	endpoint, ok := m.blockHandles[parent]
	if !ok {
		return 0, fmt.Errorf("uefi: unknown parent block handle")
	}
	if offset < 0 || size <= 0 || offset > endpoint.Size || size > endpoint.Size-offset || offset%int64(endpoint.BlockSize) != 0 || size%int64(endpoint.BlockSize) != 0 {
		return 0, fmt.Errorf("uefi: invalid partition range")
	}
	endpoint.Offset += offset
	endpoint.Size = size
	return m.attachEndpoint(endpoint, handle, devicePath, true)
}

func (m *Machine) attachEndpoint(endpoint blockEndpoint, handle uint64, path []byte, partition bool) (uint64, error) {
	if len(path) > 4096 {
		return 0, fmt.Errorf("uefi: device path exceeds a page")
	}
	if handle == 0 {
		handle = m.allocate(0, 4, 1, 0)
		if handle == 0 {
			return 0, fmt.Errorf("uefi: no handle memory")
		}
	}
	if m.protocols[handle][blockIOGUID] != 0 {
		return 0, fmt.Errorf("uefi: block handle already attached")
	}
	base := m.allocate(0, 4, 2, 0)
	if base == 0 {
		return 0, fmt.Errorf("uefi: no block protocol memory")
	}
	media := base + 64
	diskio := base + 128
	endpoint.Handle = handle
	m.u64(base, 0x20031)
	m.u64(base+8, media)
	for j, name := range []string{"Block.Reset", "Block.Read", "Block.Write", "Block.Flush"} {
		m.u64(base+16+uint64(j)*8, m.gate(name))
	}
	m.u32(media, 1)
	m.put(media+5, []byte{1})
	if partition {
		m.put(media+6, []byte{1})
	}
	if endpoint.ReadOnly {
		m.put(media+7, []byte{1})
	}
	m.u32(media+12, endpoint.BlockSize)
	m.u32(media+16, 1)
	m.u64(media+24, uint64(endpoint.Size/int64(endpoint.BlockSize)-1))
	m.u32(media+40, 1)
	m.u64(diskio, 0x10000)
	m.u64(diskio+8, m.gate("Disk.Read"))
	m.u64(diskio+16, m.gate("Disk.Write"))
	if m.protocols[handle] == nil {
		m.protocols[handle] = map[string]uint64{}
	}
	m.protocols[handle][blockIOGUID] = base
	m.protocols[handle][diskIOGUID] = diskio
	if len(path) != 0 {
		m.put(base+page, path)
		m.protocols[handle][devicePathGUID] = base + page
	}
	m.blockHandles[handle] = endpoint
	m.blockInterfaces[base] = endpoint
	m.blockInterfaces[diskio] = endpoint
	if m.err != nil {
		return 0, m.err
	}
	return handle, nil
}

func (m *Machine) blockCall(name string, a [8]uint64) uint64 {
	endpoint, ok := m.blockInterfaces[a[0]]
	if !ok {
		return invalidParameter
	}
	if name == "Block.Reset" || name == "Block.Flush" {
		return 0
	}
	if a[1] != 1 {
		return efiError | 13
	} // EFI_MEDIA_CHANGED
	offset, size := a[2], a[3]
	if name == "Block.Read" || name == "Block.Write" {
		if size%uint64(endpoint.BlockSize) != 0 {
			return efiError | 4
		}
		if offset > uint64(endpoint.Size)/uint64(endpoint.BlockSize) {
			return invalidParameter
		}
		offset *= uint64(endpoint.BlockSize)
	}
	if offset > uint64(endpoint.Size) || size > uint64(endpoint.Size)-offset {
		return invalidParameter
	}
	if size > m.opts.Memory {
		return outOfResources
	}
	if size == 0 {
		return 0
	}
	if a[4] == 0 {
		return invalidParameter
	}
	store := m.diskStores[endpoint.Store].overlay
	absolute := endpoint.Offset + int64(offset)
	if name == "Block.Write" || name == "Disk.Write" {
		if endpoint.ReadOnly {
			return efiError | 8
		}
		data := m.get(a[4], size)
		if m.err != nil {
			return invalidParameter
		}
		n, err := store.WriteAt(data, absolute)
		if err != nil || n != len(data) {
			return efiError | 7
		}
	} else {
		data := make([]byte, int(size))
		if _, err := block.ReadFullAt(store, data, absolute); err != nil {
			return efiError | 7
		}
		m.put(a[4], data)
	}
	m.emit(Event{Kind: "disk", Name: name, PC: m.processor.PC(), Address: uint64(absolute), Size: size, Args: a})
	return 0
}

func (s diskStore) clone() (diskStore, error) {
	snapshot, err := s.overlay.Snapshot()
	if err != nil {
		return diskStore{}, err
	}
	base, err := block.NewFileDevice(snapshot, block.FileDeviceOptions{LogicalBlockSize: s.overlay.Geometry().LogicalBlockSize})
	if err != nil {
		return diskStore{}, err
	}
	overlay, err := blockstar.NewOverlayDevice(base, s.limit, 64<<10)
	if err != nil {
		return diskStore{}, err
	}
	return diskStore{overlay, s.limit}, nil
}
