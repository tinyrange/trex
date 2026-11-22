// Package scsi implements transport-independent SCSI targets over block devices.
package scsi

import (
	"encoding/binary"
	"fmt"
	"maps"

	"github.com/tinyrange/trex/block"
)

// Result is a SCSI command completion. Sense contains fixed-format autosense
// bytes for CHECK CONDITION; Data contains only bytes actually transferred.
type Result struct {
	Status      byte
	Data, Sense []byte
}

// Optical is a read-only 2048-byte-sector target. It has no host paths or
// process dependencies. Copying this value captures its command/sense state;
// the immutable media backing remains shared.
type Optical struct {
	media                     block.Device
	sense                     [18]byte
	stopped, ejected, prevent bool
	persistentPrevent         bool
	reserved                  bool
	reservationOwner          uint64
	mediaGeneration           uint64
	initiators                map[uint64]uint64
}

// NewOptical creates a drive. A nil medium leaves its tray empty.
func NewOptical(media block.Device) (Optical, error) {
	if media == nil {
		return Optical{}, nil
	}
	if media.Geometry().LogicalBlockSize != 2048 || media.Geometry().Size <= 0 || media.Geometry().Size%2048 != 0 {
		return Optical{}, fmt.Errorf("scsi: optical media requires complete 2048-byte sectors")
	}
	return Optical{media: media}, nil
}

// ChangeMedia replaces an immutable disc in the same drive. Physical removal
// honors both lock states while the tray is closed. An initiator's explicit
// eject opens the tray even under Persistent Prevent, allowing replacement.
// Existing initiator nexuses receive medium-changed unit attention. Their
// generation map is copied on mutation so copying Optical remains a snapshot.
func (d *Optical) ChangeMedia(media block.Device) error {
	if media == nil {
		return fmt.Errorf("scsi: missing replacement disc")
	}
	if _, err := NewOptical(media); err != nil {
		return err
	}
	if !d.ejected && (d.prevent || d.persistentPrevent) {
		return fmt.Errorf("scsi: optical medium removal is prevented")
	}
	if d.mediaGeneration == ^uint64(0) {
		return fmt.Errorf("scsi: optical media generation exhausted")
	}
	d.media = media
	d.ejected, d.stopped = false, false
	d.mediaGeneration++
	return nil
}

func (d *Optical) acknowledgeGeneration(initiator uint64) {
	d.initiators = maps.Clone(d.initiators)
	if d.initiators == nil {
		d.initiators = make(map[uint64]uint64)
	}
	d.initiators[initiator] = d.mediaGeneration
}

// CheckCondition constructs a fixed-format sense completion.
func CheckCondition(key, asc, ascq byte) Result {
	b := make([]byte, 18)
	b[0] = 0x70
	b[2] = key
	b[7] = 10
	b[12], b[13] = asc, ascq
	return Result{Status: 2, Sense: b}
}
func (d *Optical) check(key, asc, ascq byte) Result {
	r := CheckCondition(key, asc, ascq)
	copy(d.sense[:], r.Sense)
	return r
}
func allocation(data []byte, n uint32) []byte { return data[:min(uint64(len(data)), uint64(n))] }

// Execute implements the basic optical discovery/read command set. Unknown
// opcodes return an explicit error so a backend can stop at a missing feature
// instead of reporting a fabricated successful device operation.
func (d *Optical) Execute(cdb []byte) (Result, error) {
	return d.ExecuteFrom(0, cdb)
}

// ExecuteFrom executes a command from a stable transport initiator identity.
// Execute uses identity0 for targets with a single initiator connection.
func (d *Optical) ExecuteFrom(initiator uint64, cdb []byte) (Result, error) {
	if len(cdb) < 6 {
		return Result{}, fmt.Errorf("scsi: truncated CDB")
	}
	need := 6
	switch cdb[0] >> 5 {
	case 1, 2:
		need = 10
	case 4:
		need = 16
	case 5:
		need = 12
	}
	if len(cdb) < need {
		return Result{}, fmt.Errorf("scsi: truncated CDB %02x", cdb[0])
	}
	if _, seen := d.initiators[initiator]; !seen {
		d.acknowledgeGeneration(initiator)
	}
	// RELEASE from a non-owner succeeds without removing the owner's
	// reservation. INQUIRY and REQUEST SENSE remain available to all clients.
	if d.reserved && d.reservationOwner != initiator {
		switch cdb[0] {
		case 0x12, 0x03, 0x57:
		default:
			return Result{Status: 0x18}, nil
		}
	}
	if cdb[0] != 0x12 && cdb[0] != 0x03 && d.initiators[initiator] != d.mediaGeneration {
		d.acknowledgeGeneration(initiator)
		return d.check(6, 0x28, 0), nil
	}
	if cdb[0] == 0x56 || cdb[0] == 0x57 {
		// Whole-LU RESERVE/RELEASE(10). Extent and third-party requests
		// require parameter data and are not supported by this optical LU.
		for _, b := range cdb[1:9] {
			if b != 0 {
				return d.check(5, 0x24, 0), nil
			}
		}
		if cdb[0] == 0x56 {
			d.reserved, d.reservationOwner = true, initiator
		} else if d.reserved && d.reservationOwner == initiator {
			d.reserved = false
		}
		return Result{}, nil
	}
	if cdb[0] != 0x12 && cdb[0] != 0x03 && cdb[0] != 0x1b && cdb[0] != 0x1e && cdb[0] != 0x46 {
		if d.ejected || d.media == nil {
			return d.check(2, 0x3a, 0), nil
		}
		if d.stopped {
			return d.check(2, 4, 2), nil
		}
	}
	switch cdb[0] {
	case 0x00: // TEST UNIT READY: the assigned immutable medium is present.
		return Result{}, nil
	case 0x03:
		if cdb[1]&1 != 0 {
			return d.check(5, 0x24, 0), nil
		}
		b := append([]byte(nil), d.sense[:]...)
		if b[0] == 0 {
			b[0], b[7] = 0x70, 10
		}
		d.sense = [18]byte{}
		return Result{Data: allocation(b, uint32(cdb[4]))}, nil
	case 0x12:
		n := uint32(binary.BigEndian.Uint16(cdb[3:5]))
		if cdb[1]&1 != 0 {
			var b []byte
			switch cdb[2] {
			case 0:
				b = []byte{5, 0, 0, 3, 0, 0x80, 0x83}
			case 0x80:
				serial := []byte("TREXCD0001")
				b = make([]byte, 4+len(serial))
				b[0], b[1] = 5, 0x80
				binary.BigEndian.PutUint16(b[2:4], uint16(len(serial)))
				copy(b[4:], serial)
			case 0x83:
				id := []byte("TINYRNGXOPTICAL-TREXCD0001")
				b = make([]byte, 8+len(id))
				b[0], b[1] = 5, 0x83
				binary.BigEndian.PutUint16(b[2:4], uint16(len(b)-4))
				b[4], b[5], b[7] = 2, 1, byte(len(id))
				copy(b[8:], id)
			default:
				return d.check(5, 0x24, 0), nil
			}
			return Result{Data: allocation(b, n)}, nil
		}
		if cdb[2] != 0 {
			return d.check(5, 0x24, 0), nil
		}
		b := make([]byte, 36)
		b[0], b[1], b[2], b[3], b[4] = 5, 0x80, 5, 2, 31
		copy(b[8:16], "TINYRNGX")
		copy(b[16:32], "VIRTUAL DVD-ROM ")
		copy(b[32:36], "0001")
		return Result{Data: allocation(b, n)}, nil
	case 0x25:
		if cdb[8]&1 != 0 || binary.BigEndian.Uint32(cdb[2:6]) != 0 {
			return d.check(5, 0x24, 0), nil
		}
		b := make([]byte, 8)
		last := uint64(d.media.Geometry().Size/2048 - 1)
		binary.BigEndian.PutUint32(b, uint32(min(last, uint64(0xffffffff))))
		binary.BigEndian.PutUint32(b[4:], 2048)
		return Result{Data: b}, nil
	case 0x1a, 0x5a:
		return d.modeSense(cdb), nil
	case 0x46:
		return d.configuration(cdb), nil
	case 0x43:
		return d.readTOC(cdb), nil
	case 0x51:
		return d.discInformation(cdb), nil
	case 0x28, 0xa8, 0x88:
		var lba, count uint64
		switch cdb[0] {
		case 0x28:
			lba = uint64(binary.BigEndian.Uint32(cdb[2:6]))
			count = uint64(binary.BigEndian.Uint16(cdb[7:9]))
		case 0xa8:
			lba = uint64(binary.BigEndian.Uint32(cdb[2:6]))
			count = uint64(binary.BigEndian.Uint32(cdb[6:10]))
		case 0x88:
			lba = binary.BigEndian.Uint64(cdb[2:10])
			count = uint64(binary.BigEndian.Uint32(cdb[10:14]))
		}
		blocks := uint64(d.media.Geometry().Size / 2048)
		if lba > blocks || count > blocks-lba {
			return d.check(5, 0x21, 0), nil
		}
		if count > 512 {
			return Result{}, fmt.Errorf("scsi: optical transfer exceeds advertised 1MiB")
		}
		data := make([]byte, count*2048)
		if len(data) > 0 {
			n, err := d.media.ReadAt(data, int64(lba*2048))
			if n != len(data) || err != nil {
				return d.check(3, 0x11, 0), nil
			}
		}
		return Result{Data: data}, nil
	case 0x1b:
		if cdb[4]&0xf0 != 0 {
			return d.check(5, 0x24, 0), nil
		}
		start, load := cdb[4]&1 != 0, cdb[4]&2 != 0
		if start && d.media == nil {
			return d.check(2, 0x3a, 0), nil
		}
		if load && !start && d.prevent {
			return d.check(5, 0x53, 2), nil
		}
		if load {
			d.ejected = !start
		}
		d.stopped = !start
		return Result{}, nil
	case 0x1e:
		if cdb[4]&^byte(3) != 0 {
			return d.check(5, 0x24, 0), nil
		}
		// MMC selects two independent states with the Persistent bit.
		// Persistent prevent blocks physical eject requests; it does not
		// block an initiator's START STOP eject (ordinary Prevent does).
		if cdb[4]&2 != 0 {
			d.persistentPrevent = cdb[4]&1 != 0
		} else {
			d.prevent = cdb[4]&1 != 0
		}
		return Result{}, nil
	case 0x2a, 0xaa, 0x8a:
		return d.check(7, 0x27, 0), nil
	default:
		return Result{}, fmt.Errorf("scsi: unsupported optical CDB %x", cdb[:need])
	}
}
