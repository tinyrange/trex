package cc

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/tinyrange/trex/vmm"
)

// BIOS CHS translation is independent of ATA's four-bit head register.
func translatedGeometry(sectors uint64) vmm.CHSGeometry {
	for _, heads := range []uint64{16, 32, 64, 128, 255} {
		if sectors <= 1024*heads*63 || heads == 255 {
			return vmm.CHSGeometry{Cylinders: int(min(1024, max(1, sectors/(heads*63)))), Heads: int(heads), Sectors: 63}
		}
	}
	panic("unreachable")
}

// extendedDiskTransfer implements the 16-byte EDD disk address packet. The
// advertised fixed-disk subset uses segment:offset buffers, not flat addresses.
func (p *pc) extendedDiskTransfer(address uint64, write bool, flags byte) byte {
	packet, err := p.memory(address, 16)
	if err != nil || packet[0] < 16 || packet[1] != 0 {
		return 1
	}
	count := uint64(binary.LittleEndian.Uint16(packet[2:]))
	lba := binary.LittleEndian.Uint64(packet[8:])
	bufferAddress := uint64(binary.LittleEndian.Uint16(packet[6:]))*16 + uint64(binary.LittleEndian.Uint16(packet[4:]))
	binary.LittleEndian.PutUint16(packet[2:], 0)
	if count == 0 || count > 127 || write && flags & ^byte(1) != 0 {
		return 1
	}
	capacity := uint64(p.disk.Device.Geometry().Size / 512)
	if lba >= capacity || count > capacity-lba {
		return 4
	}
	buffer, err := p.memory(bufferAddress, count*512)
	if err != nil {
		return 9
	}
	var n int
	if write {
		writer, ok := p.disk.Device.(io.WriterAt)
		if !ok || p.disk.ReadOnly {
			return 3
		}
		n, err = writer.WriteAt(buffer, int64(lba)*512)
	} else {
		n, err = p.disk.Device.ReadAt(buffer, int64(lba)*512)
	}
	binary.LittleEndian.PutUint16(packet[2:], uint16(n/512))
	if err != nil || n != len(buffer) {
		return 4
	}
	if write && flags&1 != 0 {
		verified := make([]byte, len(buffer))
		n, err := p.disk.Device.ReadAt(verified, int64(lba)*512)
		if err != nil || n != len(verified) || !bytes.Equal(buffer, verified) {
			return 0x10
		}
	}
	return 0
}

func (p *pc) extendedDiskParameters(address uint64) byte {
	header, err := p.memory(address, 2)
	if err != nil || binary.LittleEndian.Uint16(header) < 26 {
		return 1
	}
	buffer, err := p.memory(address, 26)
	if err != nil {
		return 9
	}
	clear(buffer)
	binary.LittleEndian.PutUint16(buffer, 26)
	// Geometry is the BIOS logical geometry. EDD sector count remains complete
	// even when the disk exceeds the addressable CHS range.
	binary.LittleEndian.PutUint32(buffer[4:], uint32(p.biosGeometry.Cylinders))
	binary.LittleEndian.PutUint32(buffer[8:], uint32(p.biosGeometry.Heads))
	binary.LittleEndian.PutUint32(buffer[12:], uint32(p.biosGeometry.Sectors))
	binary.LittleEndian.PutUint64(buffer[16:], uint64(p.disk.Device.Geometry().Size/512))
	binary.LittleEndian.PutUint16(buffer[24:], 512)
	return 0
}

// Verify and seek are part of the EDD fixed-disk subset. Neither transfers data
// to the packet's buffer; seek only validates the destination on this device.
func (p *pc) extendedDiskPosition(address uint64, verify bool) byte {
	packet, err := p.memory(address, 16)
	if err != nil || packet[0] < 16 || packet[1] != 0 {
		return 1
	}
	count := uint64(binary.LittleEndian.Uint16(packet[2:]))
	lba := binary.LittleEndian.Uint64(packet[8:])
	capacity := uint64(p.disk.Device.Geometry().Size / 512)
	if lba >= capacity {
		return 4
	}
	if !verify {
		return 0
	}
	binary.LittleEndian.PutUint16(packet[2:], 0)
	if count == 0 || count > 127 {
		return 1
	}
	if count > capacity-lba {
		return 4
	}
	var sector [512]byte
	for i := uint64(0); i < count; i++ {
		n, err := p.disk.Device.ReadAt(sector[:], int64(lba+i)*512)
		if err != nil || n != len(sector) {
			return 4
		}
		binary.LittleEndian.PutUint16(packet[2:], uint16(i+1))
	}
	return 0
}
