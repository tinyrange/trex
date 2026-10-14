package cc

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/block"
)

// virtioPCIBlock provides block configuration and requests over the shared
// PCI transport, using OASIS VirtIO 1.2 section 5.2.
type virtioPCIBlock struct {
	*virtioPCI
	disk block.Device
}

func newVirtioPCIBlock(configBase uint64, bar uint32, disk block.Device, memory func(uint64, uint64, bool) ([]byte, error), msi func(uint64, uint32) error) *virtioPCIBlock {
	v := &virtioPCIBlock{disk: disk}
	v.virtioPCI = newVirtioPCI(virtioPCIOptions{
		ConfigBase: configBase, BAR: bar,
		VendorID: 0x1af4, DeviceID: 0x1042, SubsystemVendorID: 0x1af4, SubsystemID: 2,
		Revision: 1, Class: 1, Subclass: 0x80,
		Offered: v.offered, DeviceConfig: v.deviceConfig, Request: v.request,
	}, memory, msi)
	return v
}
func (v *virtioPCIBlock) offered(selectID uint32) uint32 {
	if selectID == 1 {
		return 1
	} // VIRTIO_F_VERSION_1
	if selectID != 0 {
		return 0
	}
	f := uint32(1 << 6) // BLK_SIZE
	if !v.disk.Capabilities().Writable {
		f |= 1 << 5
	}
	if v.disk.Capabilities().Flush {
		f |= 1 << 9
	}
	return f
}
func (v *virtioPCIBlock) deviceConfig() (c [64]byte) {
	binary.LittleEndian.PutUint64(c[:], uint64(v.disk.Geometry().Size)/512)
	binary.LittleEndian.PutUint32(c[20:], 512)
	return c
}
func (v *virtioPCIBlock) request(parts []virtioBuffer) (uint32, error) {
	var total uint64
	for _, part := range parts {
		total += uint64(len(part.data))
	}
	if len(parts) < 2 || parts[0].write || len(parts[0].data) != 16 || !parts[len(parts)-1].write || len(parts[len(parts)-1].data) != 1 {
		return 0, fmt.Errorf("virtio PCI block: invalid request framing")
	}
	header := parts[0].data
	kind := binary.LittleEndian.Uint32(header)
	sector := binary.LittleEndian.Uint64(header[8:])
	data := parts[1 : len(parts)-1]
	status := parts[len(parts)-1].data
	length := total - 17
	statusValue := byte(0)
	written := uint32(1)
	switch kind {
	case 0, 1:
		for _, p := range data {
			if p.write != (kind == 0) {
				return 0, fmt.Errorf("virtio PCI block: wrong descriptor direction")
			}
		}
		if length%512 != 0 || sector > uint64(v.disk.Geometry().Size)/512 || length > uint64(v.disk.Geometry().Size)-sector*512 {
			statusValue = 1
			break
		}
		writer, canWrite := v.disk.(block.Writer)
		if kind == 1 && (!canWrite || !v.disk.Capabilities().Writable) {
			statusValue = 1
			break
		}
		offset := int64(sector * 512)
		// Read to a bounded temporary buffer so disk errors never partially DMA.
		buffer := make([]byte, length)
		if kind == 0 {
			n, err := v.disk.ReadAt(buffer, offset)
			if n != len(buffer) || err != nil && err != io.EOF {
				statusValue = 1
				break
			}
			at := 0
			for _, p := range data {
				at += copy(p.data, buffer[at:])
			}
			written += uint32(length)
		} else {
			at := 0
			for _, p := range data {
				at += copy(buffer[at:], p.data)
			}
			n, err := writer.WriteAt(buffer, offset)
			if n != len(buffer) || err != nil {
				statusValue = 1
			}
		}
	case 4:
		flusher, ok := v.disk.(block.Flusher)
		if length != 0 || !ok || !v.disk.Capabilities().Flush {
			statusValue = 2
		} else if err := flusher.Flush(); err != nil {
			statusValue = 1
		}
	case 8:
		if length < 20 {
			statusValue = 1
			break
		}
		for _, p := range data {
			if !p.write {
				return 0, fmt.Errorf("virtio PCI block: ID buffer is not writable")
			}
		}
		id := [20]byte{}
		copy(id[:], "trex-vserver-disk")
		at := 0
		for _, p := range data {
			if at < 20 {
				at += copy(p.data, id[at:])
			}
		}
		written += 20
	default:
		statusValue = 2
	}
	status[0] = statusValue
	return written, nil
}
