package scsi

import "encoding/binary"

// configuration implements MMC GET CONFIGURATION's ordered feature query.
// The virtual medium is a read-only DVD-ROM with 2048-byte logical blocks.
func (d *Optical) configuration(cdb []byte) Result {
	rt := cdb[1] & 3
	if cdb[1]&^byte(3) != 0 || rt == 3 || cdb[4] != 0 || cdb[5] != 0 || cdb[6] != 0 {
		return d.check(5, 0x24, 0)
	}
	start := binary.BigEndian.Uint16(cdb[2:4])
	present := byte(1)
	if d.ejected || d.media == nil {
		present = 0
	}
	features := [][]byte{
		{0, 0, 3, 4, 0, 0x10, present, 0},             // DVD-ROM profile list
		{0, 1, 3, 8, 0, 0, 0, 1, 0, 0, 0, 0},          // core, SCSI physical interface
		{0, 2, 3, 4, 0, 0, 0, 0},                      // polling only; no operational-change events
		{0, 3, 3, 4, 0x29, 0, 0, 0},                   // tray/eject/lock, starts unlocked
		{0, 0x10, present, 8, 0, 0, 8, 0, 0, 1, 0, 0}, // random readable, blocking1
		{0, 0x1f, present, 4, 0, 0, 0, 0},             // DVD read, no writable/dual-layer formats
	}
	b := make([]byte, 8)
	if present != 0 {
		binary.BigEndian.PutUint16(b[6:8], 0x10)
	}
	for _, f := range features {
		code := binary.BigEndian.Uint16(f)
		if code < start || (rt == 2 && code != start) || (rt == 1 && f[2]&1 == 0) {
			continue
		}
		b = append(b, f...)
	}
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))
	return Result{Data: allocation(b, uint32(binary.BigEndian.Uint16(cdb[7:9])))}
}
