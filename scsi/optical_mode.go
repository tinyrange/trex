package scsi

import "encoding/binary"

// modeSense reports the target's fixed read-only parameters. Changeable
// values contain masks, not the current settings; no parameter is writable.
func (d *Optical) modeSense(cdb []byte) Result {
	ten := cdb[0] == 0x5a
	allowed := byte(8) // disable block descriptors
	if ten {
		allowed |= 0x10
	} // LLBAA: no block descriptors are returned
	if cdb[1] & ^allowed != 0 || (cdb[3] != 0 && cdb[3] != 0xff) {
		return d.check(5, 0x24, 0)
	}
	pc, page := cdb[2]>>6, cdb[2]&63
	if pc == 3 {
		return d.check(5, 0x39, 0)
	} // saving parameters not supported
	if page != 1 && page != 0x2a && page != 0x3f {
		return d.check(5, 0x24, 0)
	}
	header, n := 4, uint32(cdb[4])
	if ten {
		header, n = 8, uint32(binary.BigEndian.Uint16(cdb[7:9]))
	}
	b := make([]byte, header)
	if ten {
		b[3] = 0x80
	} else {
		b[2] = 0x80
	} // immutable medium
	if page == 1 || page == 0x3f {
		// Read/write error recovery: no automatic reallocation or retries.
		r := make([]byte, 12)
		r[0], r[1] = 1, 10
		b = append(b, r...)
	}
	if page == 0x2a || page == 0x3f {
		// MMC CD/DVD capabilities and mechanical status, no audio/writing.
		p := make([]byte, 22)
		p[0], p[1] = 0x2a, 20
		if pc != 1 {
			p[2] = 8    // DVD-ROM read
			p[6] = 0x29 // tray, eject and locking supported
			if d.prevent {
				p[6] |= 2
			}
		}
		b = append(b, p...)
	}
	if ten {
		binary.BigEndian.PutUint16(b, uint16(len(b)-2))
	} else {
		b[0] = byte(len(b) - 1)
	}
	return Result{Data: allocation(b, n)}
}
