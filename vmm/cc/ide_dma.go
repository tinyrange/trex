package cc

import (
	"encoding/binary"
	"fmt"
	"io"

	"j5.nz/cc/hypervisor"
)

func (d *pciIDE) busMasterBase() uint32 {
	return binary.LittleEndian.Uint32(d.config[0x20:]) & 0xfffffff0
}

func (p *pc) busMasterIO(ex hypervisor.X86Exit) error {
	d := p.pciIDE
	for i := uint32(0); i < ex.Count; i++ {
		for j := uint32(0); j < uint32(ex.Size); j++ {
			pos := i*uint32(ex.Size) + j
			offset := uint32(ex.Port) - d.busMasterBase() + j
			if offset >= 16 {
				if !ex.Write {
					ex.Data[pos] = 0xff
				}
				continue
			}
			if !ex.Write {
				ex.Data[pos] = d.bm[offset]
				continue
			}
			value := ex.Data[pos]
			switch offset & 7 {
			case 0:
				d.bm[offset] = value & 9
				if value&1 == 0 {
					d.bm[offset+2] &^= 1
				}
			case 2:
				// Interrupt and error are write-one-to-clear; DMA-capable
				// drive bits are software-owned, as defined by the interface.
				d.bm[offset] = (d.bm[offset] &^ (value&6 | 0x60)) | value&0x60
			case 4:
				d.bm[offset] = value & 0xfc
			case 5, 6, 7:
				d.bm[offset] = value
			}
		}
	}
	return p.tryIDEDMA()
}

// Transfers use the guest's physical region descriptors directly against the
// portable block device. Descriptor bounds are checked before changing memory
// or disk, and each buffer must stay within its specified 64 KiB window.
func (p *pc) tryIDEDMA() error {
	d, ata := p.pciIDE, p.ide
	if d == nil || ata == nil || !ata.dmaPending || d.bm[0]&1 == 0 || d.config[4]&5 != 5 {
		return nil
	}
	d.bm[2] |= 1
	fail := func(reason string) error {
		ata.dmaError = reason
		ata.dmaPending = false
		d.bm[2] = d.bm[2]&^1 | 6
		return ata.fail(4)
	}
	if (d.bm[0]&8 == 0) != ata.write {
		return fail("direction mismatch")
	}
	type region struct{ address, size uint64 }
	var regions []region
	remaining := uint64(ata.remaining) * 512
	ptr := uint64(binary.LittleEndian.Uint32(d.bm[4:8]))
	for remaining > 0 {
		prd, err := p.memory(ptr, 8)
		if err != nil {
			return fail(fmt.Sprintf("descriptor %#x: %v", ptr, err))
		}
		address := uint64(binary.LittleEndian.Uint32(prd)) &^ 1
		size := uint64(binary.LittleEndian.Uint16(prd[4:])) &^ 1
		if size == 0 {
			size = 65536
		}
		if address&0xffff+size > 65536 {
			return fail(fmt.Sprintf("buffer %#x size %#x crosses 64 KiB", address, size))
		}
		count := min(size, remaining)
		if _, err = p.memory(address, count); err != nil {
			return fail(fmt.Sprintf("buffer %#x size %#x: %v", address, count, err))
		}
		regions = append(regions, region{address, count})
		remaining -= count
		if remaining != 0 && prd[7]&0x80 != 0 {
			return fail("descriptor chain ended before transfer")
		}
		ptr += 8
	}
	offset := ata.lba * 512
	for _, r := range regions {
		buffer, _ := p.memory(r.address, r.size)
		var n int
		var err error
		if ata.write {
			writer, ok := ata.disk.Device.(io.WriterAt)
			if !ok || ata.disk.ReadOnly {
				return fail("disk is not writable")
			}
			n, err = writer.WriteAt(buffer, offset)
		} else {
			n, err = ata.disk.Device.ReadAt(buffer, offset)
		}
		if err != nil || n != len(buffer) {
			return fail(fmt.Sprintf("block transfer at %#x: %d/%d bytes: %v", offset, n, len(buffer), err))
		}
		offset += int64(n)
	}
	for ata.remaining > 0 {
		ata.advance()
	}
	ata.dmaPending = false
	ata.task[7] = 0x50
	d.bm[2] = d.bm[2]&^1 | 4
	return ata.signal(true)
}
