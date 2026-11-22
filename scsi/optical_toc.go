package scsi

import "encoding/binary"

// readTOC describes the assigned image's single complete data session. The
// lead-out is the actual end of the block device, never a fixed disc size.
func (d *Optical) readTOC(cdb []byte) Result {
	format := cdb[2] & 15
	if cdb[1]&^byte(2) != 0 || cdb[2]&0xf0 != 0 || format > 1 {
		return d.check(5, 0x24, 0)
	}
	start := cdb[6]
	if format == 0 && start != 0 && start != 1 && start != 0xaa {
		return d.check(5, 0x24, 0)
	}
	b := []byte{0, 0, 1, 1}
	appendTrack := func(track byte, lba uint64) bool {
		p := make([]byte, 8)
		p[1], p[2] = 0x14, track // ADR1, data track
		if cdb[1]&2 != 0 {
			frames := lba + 150
			if frames/4500 > 255 {
				return false
			}
			p[5], p[6], p[7] = byte(frames/4500), byte(frames/75%60), byte(frames%75)
		} else {
			if lba > 0xffffffff {
				return false
			}
			binary.BigEndian.PutUint32(p[4:], uint32(lba))
		}
		b = append(b, p...)
		return true
	}
	if format == 1 || start != 0xaa {
		if !appendTrack(1, 0) {
			return d.check(5, 0x24, 0)
		}
	}
	if format == 0 {
		if !appendTrack(0xaa, uint64(d.media.Geometry().Size/2048)) {
			return d.check(5, 0x24, 0)
		}
	}
	binary.BigEndian.PutUint16(b, uint16(len(b)-2))
	return Result{Data: allocation(b, uint32(binary.BigEndian.Uint16(cdb[7:9])))}
}
