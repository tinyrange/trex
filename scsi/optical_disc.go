package scsi

import "encoding/binary"

// discInformation reports a finalized, non-erasable DVD-ROM data session.
// DVD-ROM has no writable lead-in, future lead-out, disc barcode or OPC table.
func (d *Optical) discInformation(cdb []byte) Result {
	if cdb[1] != 0 {
		return d.check(5, 0x24, 0)
	} // standard information only
	b := make([]byte, 34)
	binary.BigEndian.PutUint16(b, 32)
	b[2] = 0x0e // disc complete, last session complete, non-erasable
	b[3], b[4], b[5], b[6] = 1, 1, 1, 1
	b[7] = 0x20 // unrestricted use, no recorded disc/application/barcode IDs
	return Result{Data: allocation(b, uint32(binary.BigEndian.Uint16(cdb[7:9])))}
}
