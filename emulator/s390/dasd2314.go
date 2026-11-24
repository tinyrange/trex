package s390

import (
	"errors"
	"fmt"
	"math/bits"

	"github.com/tinyrange/trex/filesystem/ckd"
)

// The 2314 sense fields and physical track layout follow GA26-3599-6.
const (
	sense2314TrackCondition = 0x02 // sense byte 0
	sense2314SeekCheck      = 0x01 // sense byte 0
	sense2314TrackOverrun   = 0x40 // sense byte 1
	sense2314Overflow       = 0x01 // sense byte 1
	sense2314SeekIncomplete = 0x01 // sense byte 3
)

var (
	errOverflowHead2314 = errors.New("overflow to a track with the wrong head number")
	errNoRecord         = errors.New("no overflow record on next track")
)

func (d *DASD3390) trimOverflow2314(track uint32, firstRemoved int) {
	flags := d.overflow[track]
	for rec := range flags {
		if rec >= firstRemoved {
			delete(flags, rec)
		}
	}
	if len(flags) == 0 {
		delete(d.overflow, track)
	}
}

func (d *DASD3390) setOverflow2314(track uint32, rec int) {
	if d.overflow == nil {
		d.overflow = make(map[uint32]map[int]bool)
	}
	if d.overflow[track] == nil {
		d.overflow[track] = make(map[int]bool)
	}
	d.overflow[track][rec] = true
}

// An overflow segment is the first record following R0 on the next track.
func (d *DASD3390) nextOverflow2314() ([]ckd.Record, error) {
	if err := d.stepHead2314(); err != nil {
		return nil, err
	}
	ha := d.homeAddress()
	if ha[0]&0x02 != 0 {
		return nil, errTrackCondition
	}
	if uint32(be.Uint16(ha[3:])) != d.head {
		return nil, errOverflowHead2314
	}
	r, err := d.track(d.curTrack())
	if err != nil {
		return nil, err
	}
	if len(r) < 2 {
		return nil, errNoRecord
	}
	d.rec, d.afterData = 1, true
	return r, nil
}

func (d *DASD3390) overflowCheck2314(err error, op byte) byte {
	switch err {
	case errOverflowHead2314:
		d.check(sense2314SeekCheck, 0, 0, err.Error())
	case errNoRecord:
		d.check(0, senseNoRecord, 0, err.Error())
	default:
		d.ioErr(err)
	}
	d.sense[1] |= sense2314Overflow
	d.sense[5] = op
	return d.ok() | usUnitCheck
}

func (d *DASD3390) readOverflow2314(out []byte) ([]byte, byte) {
	for d.overflow[d.curTrack()][d.rec] {
		r, err := d.nextOverflow2314()
		if err != nil {
			return out, d.overflowCheck2314(err, 0x06)
		}
		out = append(out, r[d.rec].Data...)
		d.markRecord(d.curTrack(), r[d.rec].Number)
	}
	return out, d.ok()
}

// diskWrite2314 describes the fields selected by a write. The channel
// supplies the actual byte count when the transfer ends.
type diskWrite2314 struct {
	Data   []byte
	Fields []diskWriteField2314
}

type diskWriteField2314 struct {
	Track  uint32
	Record int
	Key    bool
}

func (d *DASD3390) writeData2314(data []byte, key bool, deferred *diskWrite2314) ([]byte, int, byte) {
	if !d.writeAllowed(false) {
		return d.check(0, senseFileProtect, 0, "write inhibited")
	}
	r, err := d.track(d.curTrack())
	if err != nil {
		return d.ioErr(err)
	}
	// A successful Search ID or Search Key has already selected the
	// record on a valid 2314 write chain.
	if d.rec < 0 || d.rec >= len(r) || d.afterData {
		return d.check(0, senseNoRecord, 0, "write data: no record selected")
	}
	write := diskWrite2314{Data: data}
	size := 0
	status := d.ok()
	for {
		record := &r[d.rec]
		write.Fields = append(write.Fields, diskWriteField2314{d.curTrack(), d.rec, key})
		if key {
			size += len(record.Key)
			key = false
		}
		size += len(record.Data)
		d.afterData = true
		if !d.overflow[d.curTrack()][d.rec] {
			if len(record.Data) == 0 {
				status |= usUnitExcept
			}
			break
		}
		r, err = d.nextOverflow2314()
		if err != nil {
			status = d.overflowCheck2314(err, 0x05)
			break
		}
	}
	used := min(size, len(data))
	if deferred != nil {
		*deferred = write
	} else if err := d.commitWrite2314(&write, used, false); err != nil {
		return d.ioErr(err)
	}
	return nil, used, status
}

func (d *DASD3390) commitWrite2314(write *diskWrite2314, used int, halted bool) error {
	data := write.Data[:used]
	d.Stats.Writes++
	for i, field := range write.Fields {
		if halted && i > 0 && len(data) == 0 {
			break
		}
		r, err := d.writable(field.Track)
		if err != nil {
			return err
		}
		record := &r[field.Record]
		if field.Key {
			n := copy(record.Key, data)
			clear(record.Key[n:])
			data = data[n:]
		}
		n := copy(record.Data, data)
		clear(record.Data[n:])
		data = data[n:]
		if halted {
			d.cyl, d.head = field.Track/d.heads, field.Track%d.heads
			d.rec, d.afterData, d.afterKey = field.Record, true, false
		}
	}
	return nil
}

func (d *DASD3390) recalibrate() {
	d.cyl, d.head, d.rec, d.indexPass = 0, 0, -1, 0
	d.seekIncomplete, d.afterData, d.afterKey = false, false, false
}

func (d *DASD3390) seek2314(cmd byte, data []byte, earlySeek bool) ([]byte, int, byte) {
	const count = 6
	if len(data) >= count {
		cyl := uint32(be.Uint16(data[2:]))
		head := uint32(be.Uint16(data[4:]))
		valid := cmd == 0x1b || data[0]|data[1]|data[2] == 0
		if cmd == 0x1b {
			cyl = d.cyl
		}
		if valid && head < d.heads {
			if cyl < d.cylinders {
				d.cyl, d.head, d.rec, d.indexPass = cyl, head, -1, 0
				d.afterData, d.afterKey = false, false
				return nil, count, d.ok()
			}
			if earlySeek && d.cylinders == 203 {
				// The early 2314 accepts the eight-bit target into its
				// cylinder register. Beyond the pack it hits the stop
				// and fails to detent (IBM 2218323, F6BB routine 2).
				d.seekIncomplete = true
				d.check(sense2314SeekCheck, 0, 0, "seek did not detent")
				return nil, count, d.ok() | usUnitCheck
			}
		}
	}
	d.check(senseCmdReject|sense2314SeekCheck, 0, 0, fmt.Sprintf("invalid seek address %X", data))
	return nil, count, d.ok() | usUnitCheck
}

func (d *DASD3390) stepHead2314() error {
	if d.mask&0x18 == 0x18 {
		return errFileProtect
	}
	if d.homeAddress()[0]&0x03 != 0 {
		return errTrackCondition
	}
	if d.head+1 == d.heads {
		return errEndOfCylinder
	}
	d.head++
	d.rec, d.indexPass = -1, 0
	d.afterData, d.afterKey = false, false
	return nil
}

// A defective track remains addressable for reformatting and for reading
// its home address and R0, which identify the alternate track.
func (d *DASD3390) checksDefect2314(cmd byte) bool {
	switch cmd & 0x7f {
	case 0x01, 0x05, 0x06, 0x0d, 0x0e, 0x0f, 0x11, 0x12, 0x1d, 0x1e,
		0x25, 0x29, 0x2d, 0x31, 0x35, 0x45, 0x49, 0x4d, 0x51, 0x55, 0x65, 0x69, 0x6d, 0x71, 0x75:
		return d.homeAddress()[0]&0x02 != 0
	}
	return false
}

func (d *DASD3390) searchHA2314(cmd byte, data []byte) ([]byte, int, byte) {
	if cmd&0x80 != 0 {
		if err := d.stepHead2314(); err != nil {
			return d.ioErr(err)
		}
	}
	d.rec, d.indexPass = -1, 0
	d.afterData, d.afterKey = false, false
	ha := d.homeAddress()
	if compareBytes(ha[1:], data) != 0 {
		return d.check(0, senseNoRecord, 0, "search home address: no match")
	}
	if len(data) >= 4 {
		d.searchMatch = cmd
	}
	return nil, 4, d.ok() | usSM
}

func (d *DASD3390) lengthOnCheck2314(cmd byte) bool {
	switch cmd & 0x7f {
	case 0x07, 0x0b, 0x1b, 0x1a, 0x29, 0x31, 0x39, 0x49, 0x51, 0x69, 0x71:
		return true
	case 0x0f, 0x06, 0x0e, 0x16, 0x1e, 0x05, 0x0d, 0x2d, 0x4d, 0x6d,
		0x25, 0x35, 0x45, 0x55, 0x65, 0x75:
		// EOF may end a command with bytes left in the CCW. Space
		// count can likewise stop at index before moving any bytes.
		return true
	case 0x01, 0x15, 0x1d:
		return d.sense[1]&sense2314TrackOverrun != 0
	}
	return false
}

// Space Count leaves the disk positioned at an otherwise unreadable count
// area so the following read can recover data (GA26-3599-6 pp. 38–39).
func (d *DASD3390) spaceCount2314(prev byte, data []byte) ([]byte, int, byte) {
	if formatWrite2314(prev) || prev == 0x05 || prev == 0x0d || prev == 0x11 {
		d.formatErase = formatWrite2314(prev)
		d.check(senseCmdReject, 0x10, 0, "space count after write")
		return nil, 0, usUnitCheck
	}
	r, err := d.track(d.curTrack())
	if err != nil {
		return d.ioErr(err)
	}
	if prev == 0 || prev == 0x03 {
		d.rec = 0 // bypass the home address and R0
	} else {
		d.rec++
	}
	if d.rec >= len(r) {
		return d.check(0, senseNoRecord, 0, "space count: index before address marker")
	}
	d.afterData, d.afterKey = false, false
	d.mask = d.mask&0x3f | 0x40 // Space Count inhibits all subsequent writes.
	d.spaceLengths = [3]byte{}
	copy(d.spaceLengths[:], data)
	return nil, min(3, len(data)), d.ok()
}

func (d *DASD3390) readSpaced2314(readKey bool) ([]byte, int, byte) {
	record, ok, out, used, status := d.positionForRead(false, false, false)
	if !ok {
		return out, used, status
	}
	d.afterData = true
	d.Stats.Reads++
	d.markRecord(d.curTrack(), record.Number)
	keyLen, dataLen := int(d.spaceLengths[0]), int(be.Uint16(d.spaceLengths[1:]))
	if readKey {
		out = d.recoverField2314(out, record.Key, keyLen)
	}
	out = d.recoverField2314(out, record.Data, dataLen)
	if keyLen != len(record.Key) || dataLen != len(record.Data) {
		d.check(senseDataCheck, 0, 0, "space count: supplied lengths differ from recorded lengths")
		return out, 0, d.ok() | usUnitCheck
	}
	status = d.ok()
	if dataLen == 0 {
		status |= usUnitExcept
	}
	return out, 0, status
}

// In a recovery read the supplied lengths replace the missing count field.
// An overlong field may therefore expose the checks and the following gap.
func (d *DASD3390) recoverField2314(out, field []byte, length int) []byte {
	out = append(out, field[:min(length, len(field))]...)
	if length <= len(field) {
		return out
	}
	// The paired check registers start at all ones and XOR alternating
	// bytes (2841 FETOM, section 1.4.4.4). Emit them in read order.
	cc := [2]byte{0xff, 0xff}
	bitCount := 2 // one bits in the sync byte immediately before the field
	for i, b := range field {
		cc[i&1] ^= b
		bitCount += bits.OnesCount8(b)
	}
	first, second := cc[len(field)&1], cc[(len(field)+1)&1]
	bitCount += bits.OnesCount8(first)
	// The 2314 follows the code checks with the drive indicator and
	// complemented bit count (GA26-3599-6, figure 12).
	trailer := [4]byte{first, second, byte(d.devno), ^byte(bitCount)}
	extra := length - len(field)
	out = append(out, trailer[:min(extra, len(trailer))]...)
	for i := 0; i < min(extra-len(trailer), 41); i++ {
		out = append(out, 0xff)
	}
	return out
}

// Search Key and Data compares the logical record to the argument. Continue
// Scan compares only data. Both treat FF in the argument as a masked byte.
func (d *DASD3390) scan2314(cmd, prev byte, data []byte, mt bool) ([]byte, int, byte) {
	if prev == 0 && cmd&0x08 != 0 {
		d.rec, d.afterData, d.afterKey = -1, false, false
	}
	record, ok, out, used, status := d.positionForRead(mt, false, false)
	if !ok {
		return out, used, status
	}
	d.afterData = true
	var field []byte
	if cmd&0x08 != 0 {
		field = append(field, record.Key...)
	}
	field = append(field, record.Data...)
	if len(record.Data) == 0 {
		return nil, len(field), d.ok() | usUnitExcept
	}
	field, status = d.readOverflow2314(field)
	compare := 0
	for i, want := range data[:min(len(data), len(field))] {
		if want != 0xff && field[i] != want {
			compare = int(field[i]) - int(want)
			break
		}
	}
	mode := cmd & 0x60
	if status&usUnitCheck != 0 {
		switch {
		case compare == 0:
			d.sense[5] = mode | 0x05
		case compare < 0 || mode == 0x20:
			d.sense[5] = 0x55
		default:
			d.sense[5] = 0x75
		}
		return nil, len(field), status
	}
	match := mode == 0x20 && compare == 0 || mode == 0x40 && compare > 0 || mode == 0x60 && compare >= 0
	if cmd&0x10 != 0 {
		match = cmd != 0x55
	}
	if match {
		d.indexPass = 0
		status |= usSM
	}
	return nil, len(field), status
}

// The last record need only fit through its data field. Earlier records
// include the interrecord gaps and read-back check interval (Fig. 14).
func (d *DASD3390) fits2314(records []ckd.Record, keyLen, dataLen int) bool {
	available := 7403
	if d.homeAddress()[0]&0x40 != 0 {
		available -= 705
	}
	for _, r := range records {
		gaps := 101
		if len(r.Key) != 0 {
			gaps = 146
		}
		available -= gaps + 534*(len(r.Key)+len(r.Data))/512
	}
	if keyLen != 0 {
		keyLen += 45
	}
	return keyLen+dataLen <= available
}
