package s390

import (
	"errors"
	"fmt"
	"io"

	"github.com/tinyrange/trex/filesystem/ckd"
	"github.com/tinyrange/trex/storage"
)

// TrackSource supplies the tracks of a CKD volume.
type TrackSource interface {
	Track(track uint32) ([]ckd.Record, error)
}

// DASD3390 is a CKD direct-access device (a 3390 on a 3990 storage control
// by default, or an earlier type such as the 3330 or 3350) with an in-memory
// overlay for written tracks. The base volume is never modified.
type DASD3390 struct {
	base      TrackSource
	cylinders uint32
	heads     uint32
	devType   uint16
	overlay   map[uint32][]ckd.Record
	cache     map[uint32]*trackEntry
	lru       trackEntry // sentinel of the most-recently-used list
	cacheSize int        // decoded bytes held in cache
	ReadOnly  bool
	devno     uint16

	// positioning
	cyl, head uint32
	rec       int  // index of the record whose count area was last passed; -1 = at index (before R0 count)
	afterData bool // orientation past the data area of rec (false: after count)
	afterKey  bool
	indexPass int

	// extent / locate record
	extent     bool
	mask       byte
	extBeg     uint32 // begin track
	extEnd     uint32 // end track
	locate     bool
	lrOp       byte
	lrCount    int
	lrOrient   byte
	lrSearch   [5]byte
	lrSearched bool
	lrFirst    bool

	sense    [32]byte
	rssd     byte // suborder of the last prepare-for-read-subsystem-data
	reserved bool
	pgid     [11]byte
	chained  bool
	prevCmd  byte
	Stats    DASDStats
	lastErr  error
}

type DASDStats struct {
	Reads, Writes, Commands uint64
	Errors                  []string
}

// NewDASD3390 creates a device over a CKD volume with the given number of
// cylinders and 15 heads.
func NewDASD3390(base TrackSource, cylinders uint32) *DASD3390 {
	return NewDASD(base, 0x3390, cylinders, 15)
}

// NewDASD creates a CKD device of a type (0x3390, 0x3380, 0x3375, 0x3350,
// 0x3340, 0x3330, 0x2314) over a volume.
func NewDASD(base TrackSource, devType uint16, cylinders, heads uint32) *DASD3390 {
	return &DASD3390{base: base, cylinders: cylinders, heads: heads, devType: devType, overlay: map[uint32][]ckd.Record{}, cache: map[uint32]*trackEntry{}, rec: -1}
}

// DASDTypes maps a CKD image device code to the device type and heads.
var DASDTypes = map[byte]struct {
	Type  uint16
	Heads uint32
}{
	0x90: {0x3390, 15}, 0x80: {0x3380, 15}, 0x75: {0x3375, 12}, 0x50: {0x3350, 30},
	0x40: {0x3340, 12}, 0x30: {0x3330, 19}, 0x14: {0x2314, 20},
}

// eckd reports whether the device has a storage control with extended
// count-key-data commands (Define Extent, Locate Record, RDC, Sense ID).
func (d *DASD3390) eckd() bool { return d.devType == 0x3390 || d.devType == 0x3380 }

// senseLen is the sense-data length of the device's storage control.
func (d *DASD3390) senseLen() int {
	switch d.devType {
	case 0x2314:
		return 6
	case 0x3390, 0x3380:
		return 32
	}
	return 24
}

// Overlay returns the written tracks.
func (d *DASD3390) Overlay() map[uint32][]ckd.Record { return d.overlay }

// Cylinders returns the device's cylinder count.
func (d *DASD3390) Cylinders() uint32 { return d.cylinders }

// ReadTrack returns the current content of a track (overlay first).
func (d *DASD3390) ReadTrack(t uint32) ([]ckd.Record, error) { return d.track(t) }

func (d *DASD3390) track(t uint32) ([]ckd.Record, error) {
	if r, ok := d.overlay[t]; ok {
		return r, nil
	}
	if e, ok := d.cache[t]; ok {
		e.unlink()
		d.lru.push(e)
		return e.recs, nil
	}
	r, err := d.base.Track(t)
	if err != nil {
		return nil, err
	}
	if d.lru.next == nil {
		d.lru.next, d.lru.prev = &d.lru, &d.lru
	}
	e := &trackEntry{t: t, recs: r, size: 64}
	for _, x := range r {
		e.size += 8 + len(x.Key) + len(x.Data)
	}
	d.cache[t] = e
	d.lru.push(e)
	d.cacheSize += e.size
	for d.cacheSize > trackCacheBytes && d.lru.prev != e {
		old := d.lru.prev
		old.unlink()
		delete(d.cache, old.t)
		d.cacheSize -= old.size
	}
	return r, nil
}

// trackCacheBytes bounds the decoded base tracks a volume keeps. Reading a
// track of a compressed image restarts its decoder, so the working set
// (VTOC, catalogs, directories, link-list libraries) stays cached.
const trackCacheBytes = 1 << 30

// uncache drops a base track that the overlay now supersedes.
func (d *DASD3390) uncache(t uint32) {
	if e, ok := d.cache[t]; ok {
		e.unlink()
		delete(d.cache, t)
		d.cacheSize -= e.size
	}
}

// trackEntry is a cached base track in a most-recently-used list.
type trackEntry struct {
	prev, next *trackEntry
	t          uint32
	recs       []ckd.Record
	size       int
}

func (e *trackEntry) unlink() {
	e.prev.next, e.next.prev = e.next, e.prev
}

// push inserts e after the sentinel l (most recently used).
func (l *trackEntry) push(e *trackEntry) {
	e.prev, e.next = l, l.next
	l.next.prev = e
	l.next = e
}

// writable returns a private copy of a track for modification.
func (d *DASD3390) writable(t uint32) ([]ckd.Record, error) {
	if r, ok := d.overlay[t]; ok {
		return r, nil
	}
	r, err := d.track(t)
	if err != nil {
		return nil, err
	}
	cp := make([]ckd.Record, len(r))
	for i, x := range r {
		cp[i] = ckd.Record{Cylinder: x.Cylinder, Head: x.Head, Number: x.Number, Key: append([]byte(nil), x.Key...), Data: append([]byte(nil), x.Data...)}
	}
	d.overlay[t] = cp
	d.uncache(t)
	return cp, nil
}

var (
	errFileProtect   = errors.New("file protected: the file mask inhibits the operation")
	errEndOfCylinder = errors.New("end of cylinder")
)

// ioErr reports a track access error as unit check with sense data.
func (d *DASD3390) ioErr(err error) ([]byte, int, byte) {
	switch err {
	case errFileProtect:
		return d.check(0, senseFileProtect, 0, err.Error())
	case errEndOfCylinder:
		return d.check(0, senseEndOfCyl, 0, err.Error())
	}
	return d.check(senseDataCheck, 0, 0, err.Error())
}

func (d *DASD3390) curTrack() uint32 { return d.cyl*d.heads + d.head }

func (d *DASD3390) SenseID() []byte {
	if d.devType == 0x3380 {
		return []byte{0xff, 0x38, 0x80, 0x23, 0x33, 0x80, 0x02, 0x00}
	}
	return []byte{0xff, 0x39, 0x90, 0xe9, 0x33, 0x90, 0x0a, 0x00,
		0x40, 0xfa, 0x01, 0x00, // CIW: read configuration data
	}
}

// LDLVolume is a 3390 in the Linux disk layout: every track holds twelve
// keyless 4096-byte records (blocks numbered from track 0, record 1). Block 2
// is the LNX1 volume label and the single partition, from block 3, holds
// Data (zero beyond its end).
type LDLVolume struct {
	Data   storage.Reader
	Volser string
}

const ldlBlocksPerTrack = 12

// LDLBlocks returns the partition capacity in 4096-byte blocks of an LDL
// 3390 with the given cylinders.
func LDLBlocks(cylinders uint32) int64 { return int64(cylinders)*15*ldlBlocksPerTrack - 3 }

func (v LDLVolume) Track(t uint32) ([]ckd.Record, error) {
	c, h := uint16(t/15), uint16(t%15)
	recs := []ckd.Record{{Cylinder: c, Head: h, Number: 0, Data: make([]byte, 8)}}
	for r := 0; r < ldlBlocksPerTrack; r++ {
		block := int64(t)*ldlBlocksPerTrack + int64(r)
		data := make([]byte, 4096)
		switch {
		case block == 2:
			copy(data, EncodeEBCDIC("LNX1"))
			copy(data[4:], ebcdicPad(v.Volser, 6))
		case block > 2:
			off := (block - 3) * 4096
			if off < v.Data.Size() {
				if _, err := v.Data.ReadAt(data[:min(4096, v.Data.Size()-off)], off); err != nil && err != io.EOF {
					return nil, err
				}
			}
		}
		recs = append(recs, ckd.Record{Cylinder: c, Head: h, Number: byte(r + 1), Data: data})
	}
	return recs, nil
}

// FormattedVolume is a newly initialized, empty CKD volume: every track
// holds record zero, and track 0 also holds the IPL1, IPL2 and VOL1 records
// of an initialized volume with the given serial and no VTOC.
type FormattedVolume struct {
	Heads  uint32
	Volser string
}

func (v FormattedVolume) Track(t uint32) ([]ckd.Record, error) {
	c, h := uint16(t/v.Heads), uint16(t%v.Heads)
	recs := []ckd.Record{{Cylinder: c, Head: h, Number: 0, Data: make([]byte, 8)}}
	if t == 0 {
		vol1 := ebcdicPad("VOL1"+v.Volser, 80)
		copy(vol1[11:16], []byte{0, 0, 0, 0, 0})
		recs = append(recs,
			ckd.Record{Number: 1, Key: EncodeEBCDIC("IPL1"), Data: make([]byte, 24)},
			ckd.Record{Number: 2, Key: EncodeEBCDIC("IPL2"), Data: make([]byte, 144)},
			ckd.Record{Number: 3, Key: EncodeEBCDIC("VOL1"), Data: vol1})
	}
	return recs, nil
}

func (d *DASD3390) Reset() {
	d.extent, d.locate = false, false
	d.rec = -1
	d.sense = [32]byte{}
}

func (d *DASD3390) StartChain() {
	d.extent, d.locate = false, false
	d.mask = 0
	d.prevCmd = 0
}
func (d *DASD3390) EndChain() {}

const (
	senseCmdReject  = 0x80
	senseIntervReq  = 0x40
	senseEquipCheck = 0x10
	senseDataCheck  = 0x08
	// byte 1
	senseNoRecord     = 0x08
	senseFileProtect  = 0x04
	senseWriteInhibit = 0x02
	senseInvalidTrack = 0x40
	senseEndOfCyl     = 0x20
)

func (d *DASD3390) check(b0, b1 byte, msg byte, why string) ([]byte, int, byte) {
	d.sense = [32]byte{}
	d.sense[0] = b0
	d.sense[1] = b1
	d.sense[7] = msg
	d.sense[24] = 0x00
	// Bytes 0-23 are in the 24-byte compatibility format, which error
	// recovery reads (file protected, no record found, ...) only when
	// this bit says so.
	d.sense[27] = 0x80
	d.noteError(why)
	return nil, 0, usCE | usDE | usUnitCheck
}

// noteError keeps the most recent 64 error descriptions.
func (d *DASD3390) noteError(why string) {
	if len(d.Stats.Errors) >= 64 {
		d.Stats.Errors = append(d.Stats.Errors[:0], d.Stats.Errors[1:]...)
	}
	d.Stats.Errors = append(d.Stats.Errors, fmt.Sprintf("%d/%d: %s", d.cyl, d.head, why))
}

func (d *DASD3390) reject(why string) ([]byte, int, byte) {
	return d.check(senseCmdReject, 0, 0x01, why)
}

func (d *DASD3390) ok() byte { return usCE | usDE }

// Exec executes one CCW command.
func (d *DASD3390) Exec(cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	d.Stats.Commands++
	prev := d.prevCmd
	d.prevCmd = cmd
	switch cmd {
	case 0x02: // read IPL
		d.cyl, d.head, d.rec = 0, 0, -1
		r, err := d.track(0)
		if err != nil {
			return d.check(0, senseDataCheck, 0, err.Error())
		}
		for i, x := range r {
			if x.Number == 1 {
				d.rec, d.afterData = i, true
				return x.Data, 0, d.ok()
			}
		}
		return d.check(0, senseNoRecord, 0, "read IPL: no record 1")
	case 0x03: // no-operation
		return nil, 0, d.ok()
	case 0x04: // sense
		s := d.sense
		d.sense = [32]byte{}
		return s[:d.senseLen()], 0, d.ok()
	case 0xe4: // sense ID
		if !d.eckd() {
			return d.reject("sense ID")
		}
		return d.SenseID(), 0, d.ok()
	case 0x64: // read device characteristics
		if d.devType != 0x3390 {
			return d.reject("read device characteristics")
		}
		return d.rdc(), 0, d.ok()
	case 0x1f: // set file mask
		if len(data) < 1 {
			return d.reject("set file mask: short")
		}
		d.mask = data[0]
		return nil, 1, d.ok()
	case 0x13: // recalibrate
		d.cyl, d.head, d.rec, d.afterData = 0, 0, -1, false
		return nil, 0, d.ok()
	case 0x17: // restore (2314): no operation
		return nil, 0, d.ok()
	case 0xfa: // read configuration data
		return d.rcd(), 0, d.ok()
	case 0x34: // sense path group ID
		out := make([]byte, 12)
		copy(out[1:], d.pgid[:])
		if d.pgid != [11]byte{} {
			out[0] = 0x80
		}
		return out, 0, d.ok()
	case 0xaf: // set path group ID
		if len(data) >= 12 {
			copy(d.pgid[:], data[1:12])
		}
		return nil, min(len(data), 12), d.ok()
	case 0x5b: // suspend multipath reconnection
		return nil, 0, d.ok()
	case 0xb4, 0x94, 0x14: // reserve, release, unconditional reserve
		d.reserved = cmd != 0x94
		return make([]byte, 32), 0, d.ok()
	case 0xa4: // read and reset buffered log
		return make([]byte, 32), 0, d.ok()
	case 0x54: // sense subsystem status
		return make([]byte, 40), 0, d.ok()
	case 0x27: // perform subsystem function
		if len(data) >= 7 && data[0] == 0x18 {
			d.rssd = data[6] // prepare for read subsystem data: suborder
		}
		return nil, len(data), d.ok()
	case 0x3e: // read subsystem data
		switch d.rssd {
		case 0x41: // feature codes: none installed
			d.rssd = 0
			return make([]byte, 256), 0, d.ok()
		case 0x0e: // unit address configuration: one base device, no aliases
			d.rssd = 0
			ua := make([]byte, 512)
			ua[0] = 0x01
			return ua, 0, d.ok()
		}
		return make([]byte, 16), 0, d.ok()
	case 0x63: // define extent
		return d.defineExtent(data)
	case 0x47: // locate record
		return d.locateRecord(data)
	case 0x07: // seek
		return d.seek(data, 6)
	case 0x0b: // seek cylinder
		return d.seek(data, 6)
	case 0x1b: // seek head
		return d.seek(data, 6)
	case 0x22: // read sector
		return []byte{0}, 0, d.ok()
	case 0x23: // set sector: rotational position only
		return nil, min(len(data), 1), d.ok()
	case 0x39: // search home address equal
		if len(data) < 4 {
			return d.reject("search HA: short")
		}
		d.rec = -1
		d.afterData = false
		cc := uint32(be.Uint16(data[0:]))
		hh := uint32(be.Uint16(data[2:]))
		if cc == d.cyl && hh == d.head {
			return nil, 4, d.ok() | usSM
		}
		return nil, 4, d.ok()
	}
	_ = prev
	mt := cmd&0x80 != 0
	base := cmd &^ 0x80
	switch base {
	case 0x31, 0x51, 0x71: // search ID equal / high / equal-or-high
		return d.searchID(base, data, mt)
	case 0x29, 0x49, 0x69: // search key equal / high / equal-or-high
		return d.searchKey(base, data, mt)
	case 0x06: // read data
		return d.readData(mt, false, false)
	case 0x0e: // read key and data
		return d.readData(mt, true, false)
	case 0x1e: // read count, key and data
		return d.readData(mt, true, true)
	case 0x12: // read count
		return d.readCount(mt)
	case 0x16: // read record zero
		return d.readR0()
	case 0x1a: // read home address
		d.rec = -1
		return []byte{0, byte(d.cyl >> 8), byte(d.cyl), byte(d.head >> 8), byte(d.head)}, 0, d.ok()
	case 0x5e: // read multiple count, key and data
		return d.readTrack()
	case 0x05: // write data
		return d.writeData(data, false)
	case 0x0d: // write key and data
		return d.writeData(data, true)
	case 0x1d: // write count, key and data (0x9D: next track)
		if mt {
			if !d.locate {
				return d.reject("write CKD next track outside a locate-record domain")
			}
			// Continue on the next track of the domain, after its R0.
			if d.head+1 >= d.heads {
				d.cyl++
				d.head = 0
			} else {
				d.head++
			}
			d.rec = 0
			d.afterData = true
			d.indexPass = 0
		}
		return d.writeCKD(data)
	case 0x01: // write special count, key and data
		return d.writeCKD(data)
	case 0x15: // write record zero
		return d.writeR0(data)
	case 0x11: // erase
		return d.erase(data)
	}
	return d.reject(fmt.Sprintf("command %02X", cmd))
}

func (d *DASD3390) seek(data []byte, n int) ([]byte, int, byte) {
	if len(data) < n {
		return d.reject("seek: short")
	}
	cc := uint32(be.Uint16(data[2:]))
	hh := uint32(be.Uint16(data[4:]))
	if cc >= d.cylinders || hh >= d.heads {
		return d.check(senseCmdReject, 0, 0x04, fmt.Sprintf("seek %d/%d out of range", cc, hh))
	}
	if d.extent {
		t := cc*d.heads + hh
		if t < d.extBeg || t > d.extEnd {
			return d.check(0, senseFileProtect, 0, "seek outside extent")
		}
	}
	d.cyl, d.head = cc, hh
	d.rec = -1
	d.afterData = false
	d.indexPass = 0
	return nil, n, d.ok()
}

// advance moves the orientation to the next count area. It returns false
// when the index point was passed twice (no record found). With mt, passing
// the index point moves to the next head.
func (d *DASD3390) advance(mt bool) ([]ckd.Record, bool, error) {
	for {
		r, err := d.track(d.curTrack())
		if err != nil {
			return nil, false, err
		}
		if d.rec+1 < len(r) {
			d.rec++
			d.afterData = false
			return r, true, nil
		}
		// index point
		d.indexPass++
		if d.indexPass > 2 && !mt {
			return r, false, nil
		}
		if mt || d.locate {
			if !d.locate && !d.extent && d.mask&0x18 == 0x18 && !d.eckd() {
				// On the 3830/3880 control units (3330, 3350) seek
				// control 11 also inhibits multitrack operations: MVS 3.8
				// IEAIPL00 relies on the resulting file-protect check at a
				// track boundary. A 3990 permits them.
				return r, false, errFileProtect
			}
			if d.locate && d.extent && d.curTrack()+1 > d.extEnd {
				// A locate-record domain may not leave the defined
				// extent: the file-protect check is how an access method
				// learns that it has read to the end of the extent.
				return r, false, errFileProtect
			}
			if d.head+1 >= d.heads {
				// Within a locate-record domain the device switches to
				// the next cylinder of the defined extent.
				if !d.locate && !d.extent {
					return r, false, errEndOfCylinder
				}
				if d.cyl+1 >= d.cylinders {
					return r, false, nil
				}
				d.cyl++
				d.head = 0
			} else {
				d.head++
			}
			d.indexPass = 0
		}
		d.rec = -1
	}
}

func (d *DASD3390) searchID(op byte, data []byte, mt bool) ([]byte, int, byte) {
	if len(data) < 5 {
		return d.reject("search ID: short")
	}
	for {
		r, ok, err := d.advance(mt)
		if err != nil {
			return d.ioErr(err)
		}
		if !ok {
			return d.check(0, senseNoRecord, 0, fmt.Sprintf("search ID %X: no record", data[:5]))
		}
		x := r[d.rec]
		id := [5]byte{byte(x.Cylinder >> 8), byte(x.Cylinder), byte(x.Head >> 8), byte(x.Head), x.Number}
		cmp := compareBytes(id[:], data[:5])
		match := false
		switch op {
		case 0x31:
			match = cmp == 0
		case 0x51:
			match = cmp > 0
		case 0x71:
			match = cmp >= 0
		}
		if match {
			d.indexPass = 0
			return nil, 5, d.ok() | usSM
		}
		// A failed search ends the command; the channel program loops
		// with a TIC. The next search examines the next count area.
		return nil, 5, d.ok()
	}
}

func (d *DASD3390) searchKey(op byte, data []byte, mt bool) ([]byte, int, byte) {
	r, err := d.track(d.curTrack())
	if err != nil {
		return d.check(senseDataCheck, 0, 0, err.Error())
	}
	// Search key examines the next key area: records without a key, and
	// record zero, are passed over within the command.
	for d.rec < 0 || d.rec >= len(r) || d.afterData || len(r[d.rec].Key) == 0 || (d.rec == 0 && r[0].Number == 0) {
		r2, ok, err := d.advance(mt)
		if err != nil {
			return d.ioErr(err)
		}
		if !ok {
			return d.check(0, senseNoRecord, 0, "search key: no record")
		}
		r = r2
		if len(r[d.rec].Key) == 0 || (d.rec == 0 && r[0].Number == 0) {
			d.afterData = true
		}
	}
	x := r[d.rec]
	k := data
	if len(k) > len(x.Key) {
		k = k[:len(x.Key)]
	}
	cmp := compareBytes(x.Key, k)
	match := false
	switch op {
	case 0x29:
		match = cmp == 0
	case 0x49:
		match = cmp > 0
	case 0x69:
		match = cmp >= 0
	}
	used := len(x.Key)
	if used > len(data) {
		used = len(data)
	}
	if match {
		d.indexPass = 0
		return nil, used, d.ok() | usSM
	}
	// The key area has passed; the next search examines the next record.
	d.afterData = true
	return nil, used, d.ok()
}

func compareBytes(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func countField(x ckd.Record) []byte {
	return []byte{byte(x.Cylinder >> 8), byte(x.Cylinder), byte(x.Head >> 8), byte(x.Head), x.Number, byte(len(x.Key)), byte(len(x.Data) >> 8), byte(len(x.Data))}
}

// positionForRead returns the record whose data the next read transfers.
func (d *DASD3390) positionForRead(mt bool, wantCount bool) (ckd.Record, bool, []byte, int, byte) {
	r, err := d.track(d.curTrack())
	if err != nil {
		_, n, s := d.check(senseDataCheck, 0, 0, err.Error())
		return ckd.Record{}, false, nil, n, s
	}
	if d.locate && d.lrFirst {
		// Locate record oriented to the searched record.
		d.lrFirst = false
		if d.rec >= 0 && d.rec < len(r) && !d.afterData && !wantCount {
			return r[d.rec], true, nil, 0, 0
		}
	}
	if wantCount || d.rec < 0 || d.afterData || d.rec >= len(r) || (d.rec == 0 && r[0].Number == 0 && !d.locate) {
		for {
			rr, ok, err := d.advance(mt)
			if err != nil {
				_, n, s := d.ioErr(err)
				return ckd.Record{}, false, nil, n, s
			}
			if !ok {
				_, n, s := d.check(0, senseNoRecord, 0, fmt.Sprintf("read: no record at %d/%d after rec %d lr op %02X count %d search %X mt %v", d.cyl, d.head, d.rec, d.lrOp, d.lrCount, d.lrSearch, mt))
				return ckd.Record{}, false, nil, n, s
			}
			if d.rec == 0 && rr[0].Number == 0 {
				continue // record zero is skipped by normal reads
			}
			r = rr
			break
		}
	}
	return r[d.rec], true, nil, 0, 0
}

func (d *DASD3390) readData(mt, key, count bool) ([]byte, int, byte) {
	x, ok, out, n, st := d.positionForRead(mt, count)
	if !ok {
		return out, n, st
	}
	var buf []byte
	if count {
		buf = append(buf, countField(x)...)
	}
	if key || count {
		buf = append(buf, x.Key...)
	}
	buf = append(buf, x.Data...)
	d.afterData = true
	d.Stats.Reads++
	if d.locate {
		d.lrCount--
	}
	if len(x.Data) == 0 && !count {
		// End-of-file record: unit exception.
		return buf, 0, d.ok() | usUnitExcept
	}
	return buf, 0, d.ok()
}

func (d *DASD3390) readCount(mt bool) ([]byte, int, byte) {
	for {
		r, ok, err := d.advance(mt)
		if err != nil {
			return d.ioErr(err)
		}
		if !ok {
			return d.check(0, senseNoRecord, 0, "read count: no record")
		}
		// Record zero is bypassed, also when a locate-record domain
		// moves to the next track; only a first read oriented to the
		// home address returns its count.
		if d.rec == 0 && r[0].Number == 0 && !(d.locate && d.lrFirst && d.lrOrient == 1) {
			continue
		}
		d.lrFirst = false
		return countField(r[d.rec]), 0, d.ok()
	}
}

func (d *DASD3390) readR0() ([]byte, int, byte) {
	r, err := d.track(d.curTrack())
	if err != nil {
		return d.check(senseDataCheck, 0, 0, err.Error())
	}
	if len(r) == 0 {
		return d.check(0, senseNoRecord, 0, "no record zero")
	}
	d.rec = 0
	d.afterData = true
	x := r[0]
	return append(append(countField(x), x.Key...), x.Data...), 0, d.ok()
}

func (d *DASD3390) readTrack() ([]byte, int, byte) {
	r, err := d.track(d.curTrack())
	if err != nil {
		return d.check(senseDataCheck, 0, 0, err.Error())
	}
	var buf []byte
	for _, x := range r[1:] {
		buf = append(buf, countField(x)...)
		buf = append(buf, x.Key...)
		buf = append(buf, x.Data...)
	}
	d.rec = len(r) - 1
	d.afterData = true
	return buf, 0, d.ok()
}

func (d *DASD3390) writeAllowed(format bool) bool {
	if d.ReadOnly {
		return false
	}
	if d.extent {
		wi := d.mask >> 6
		if wi == 1 || wi == 3 && !format || wi == 2 && format {
			// 01 inhibit all writes; 10 inhibit format writes; 11 permit update only
		}
		switch wi {
		case 1:
			return false
		case 2:
			return !format
		}
	}
	return true
}

func (d *DASD3390) writeData(data []byte, key bool) ([]byte, int, byte) {
	if !d.writeAllowed(false) {
		return d.check(0, senseFileProtect, 0, "write inhibited")
	}
	t := d.curTrack()
	r, err := d.writable(t)
	if err != nil {
		return d.check(senseDataCheck, 0, 0, err.Error())
	}
	if d.locate && d.lrFirst {
		d.lrFirst = false
	} else if d.rec < 0 || d.afterData || d.rec >= len(r) {
		if _, ok, err := d.advance(false); err != nil || !ok {
			return d.check(0, senseNoRecord, 0, "write data: no record")
		}
		r, _ = d.writable(d.curTrack())
		if d.rec == 0 && r[0].Number == 0 {
			if _, ok, _ := d.advance(false); !ok {
				return d.check(0, senseNoRecord, 0, "write data: no record")
			}
			r, _ = d.writable(d.curTrack())
		}
	}
	x := &r[d.rec]
	avail := len(data)
	n := 0
	if key {
		n = copy(x.Key, data)
		data = data[n:]
	}
	m := copy(x.Data, data)
	for i := m; i < len(x.Data); i++ {
		x.Data[i] = 0
	}
	d.afterData = true
	d.Stats.Writes++
	if d.locate {
		d.lrCount--
	}
	// A count shorter than the record is padded with zeros.
	used := n + len(x.Data)
	if used > avail {
		used = avail
	}
	return nil, used, d.ok()
}

func (d *DASD3390) writeCKD(data []byte) ([]byte, int, byte) {
	if !d.writeAllowed(true) {
		return d.check(0, senseFileProtect, 0, "format write inhibited")
	}
	if len(data) < 8 {
		return d.reject("write CKD: short")
	}
	kl := int(data[5])
	dl := int(be.Uint16(data[6:]))
	if len(data) < 8+kl+dl {
		// The count field governs; missing bytes are zero.
		data = append(data, make([]byte, 8+kl+dl-len(data))...)
	}
	t := d.curTrack()
	r, err := d.writable(t)
	if err != nil {
		return d.check(senseDataCheck, 0, 0, err.Error())
	}
	pos := d.rec + 1
	if d.locate && d.lrFirst {
		d.lrFirst = false
	}
	if pos < 0 {
		pos = 0
	}
	if pos > len(r) {
		pos = len(r)
	}
	nr := ckd.Record{Cylinder: be.Uint16(data[0:]), Head: be.Uint16(data[2:]), Number: data[4],
		Key: append([]byte(nil), data[8:8+kl]...), Data: append([]byte(nil), data[8+kl:8+kl+dl]...)}
	r = append(r[:pos], nr)
	d.overlay[t] = r
	d.rec = pos
	d.afterData = true
	d.Stats.Writes++
	if d.locate {
		d.lrCount--
	}
	return nil, 8 + kl + dl, d.ok()
}

func (d *DASD3390) writeR0(data []byte) ([]byte, int, byte) {
	if !d.writeAllowed(true) {
		return d.check(0, senseFileProtect, 0, "format write inhibited")
	}
	if len(data) < 8 {
		return d.reject("write R0: short")
	}
	kl := int(data[5])
	dl := int(be.Uint16(data[6:]))
	if len(data) < 8+kl+dl {
		data = append(data, make([]byte, 8+kl+dl-len(data))...)
	}
	t := d.curTrack()
	nr := ckd.Record{Cylinder: be.Uint16(data[0:]), Head: be.Uint16(data[2:]), Number: data[4],
		Key: append([]byte(nil), data[8:8+kl]...), Data: append([]byte(nil), data[8+kl:8+kl+dl]...)}
	d.overlay[t] = []ckd.Record{nr}
	d.uncache(t)
	d.rec = 0
	d.afterData = true
	return nil, 8 + kl + dl, d.ok()
}

func (d *DASD3390) erase(data []byte) ([]byte, int, byte) {
	if !d.writeAllowed(true) {
		return d.check(0, senseFileProtect, 0, "erase inhibited")
	}
	t := d.curTrack()
	r, err := d.writable(t)
	if err != nil {
		return d.check(senseDataCheck, 0, 0, err.Error())
	}
	if d.rec+1 < len(r) {
		d.overlay[t] = r[:d.rec+1]
	}
	return nil, len(data), d.ok()
}

func (d *DASD3390) defineExtent(data []byte) ([]byte, int, byte) {
	if len(data) < 16 {
		return d.reject("define extent: short")
	}
	if d.extent {
		return d.check(senseCmdReject, 0, 0x02, "define extent twice")
	}
	d.extent = true
	d.mask = data[0]
	bc, bh := uint32(be.Uint16(data[8:])), uint32(be.Uint16(data[10:]))
	ec, eh := uint32(be.Uint16(data[12:])), uint32(be.Uint16(data[14:]))
	d.extBeg = bc*d.heads + bh
	d.extEnd = ec*d.heads + eh
	if d.extEnd < d.extBeg || ec >= d.cylinders {
		d.extent = false
		return d.check(senseCmdReject, 0, 0x04, "define extent: invalid range")
	}
	return nil, 16, d.ok()
}

func (d *DASD3390) locateRecord(data []byte) ([]byte, int, byte) {
	if len(data) < 16 {
		return d.reject("locate record: short")
	}
	if !d.extent {
		return d.check(senseCmdReject, 0, 0x02, "locate record without define extent")
	}
	d.locate = true
	d.lrOrient = data[0] >> 6
	d.lrOp = data[0] & 0x3f
	d.lrCount = int(data[3])
	cc := uint32(be.Uint16(data[4:]))
	hh := uint32(be.Uint16(data[6:]))
	copy(d.lrSearch[:], data[8:13])
	t := cc*d.heads + hh
	if t < d.extBeg || t > d.extEnd || cc >= d.cylinders {
		return d.check(0, senseFileProtect, 0, fmt.Sprintf("locate record %d/%d outside extent", cc, hh))
	}
	d.cyl, d.head = cc, hh
	d.rec = -1
	d.afterData = false
	d.indexPass = 0
	d.lrFirst = true
	switch d.lrOp {
	case 0x03, 0x16, 0x0c, 0x0b, 0x01, 0x06, 0x00, 0x02, 0x12, 0x11:
	default:
		d.noteError(fmt.Sprintf("locate record op %02X", d.lrOp))
	}
	// Orient: search for the record named by the search argument unless the
	// operation reads from the index (read any / read tracks / format
	// write of record zero).
	r, err := d.track(t)
	if err != nil {
		return d.check(senseDataCheck, 0, 0, err.Error())
	}
	searchRec := data[12]
	if d.lrOp == 0x0c { // read tracks: from the index
		d.rec = 0
		d.afterData = true
		d.lrFirst = false
		return nil, 16, d.ok()
	}
	if d.lrOp == 0x03 && searchRec == 0 && d.lrOrient == 1 {
		// Format write after the home address: record zero is rewritten.
		d.rec = -1
		return nil, 16, d.ok()
	}
	for i, x := range r {
		id := [5]byte{byte(x.Cylinder >> 8), byte(x.Cylinder), byte(x.Head >> 8), byte(x.Head), x.Number}
		if id == d.lrSearch {
			d.rec = i
			switch {
			case d.lrOp == 0x03:
				// Format write: records are written after the searched one.
				d.afterData = true
				d.lrFirst = false
			case d.lrOrient == 2 || d.lrOrient == 3:
				d.afterData = false
			default:
				d.afterData = false
			}
			return nil, 16, d.ok()
		}
	}
	return d.check(0, senseNoRecord, 0, fmt.Sprintf("locate record: no record %X on %d/%d", d.lrSearch, cc, hh))
}

func (d *DASD3390) rdc() []byte {
	b := make([]byte, 64)
	be.PutUint16(b[0:], 0x3990)
	b[2] = 0xe9
	be.PutUint16(b[3:], 0x3390)
	b[5] = 0x0a
	b[6] = 0xd0
	b[10] = 0x20 // DASD
	b[11] = 0x26 // 3390
	cyl := d.cylinders
	if cyl > 0xfff0 {
		be.PutUint16(b[12:], 0xfffe)
	} else {
		be.PutUint16(b[12:], uint16(cyl))
	}
	be.PutUint16(b[14:], uint16(d.heads))
	b[16] = 224
	b[17], b[18], b[19] = 0x00, 0xe5, 0xa2
	be.PutUint16(b[20:], 0x0000)
	b[22] = 0x02
	b[23], b[24], b[25], b[26], b[27] = 34, 19, 9, 6, 116
	be.PutUint16(b[28:], uint16(cyl*d.heads))
	be.PutUint16(b[30:], 15)
	be.PutUint16(b[32:], uint16((cyl+1)*d.heads))
	be.PutUint16(b[34:], 15)
	b[40] = 0x06
	b[41] = 0x06
	b[42] = 0x00
	be.PutUint16(b[44:], 0xdfee)
	be.PutUint32(b[60:], cyl)
	return b
}

// SetDeviceNumber records the device number reported in configuration
// data: its low byte is the unit address and its high byte selects the
// control unit, so each control unit is a separate storage subsystem.
func (d *DASD3390) SetDeviceNumber(devno uint16) { d.devno = devno }

func (d *DASD3390) rcd() []byte {
	// Five 32-byte node-element descriptors (device, string, storage
	// director, token), then the general node-element qualifier at 224.
	b := make([]byte, 256)
	serial := fmt.Sprintf("0000000123%02X", d.devno>>8)
	ned := func(off int, hdr uint32, devtype, model string) {
		be.PutUint32(b[off:], hdr)
		copy(b[off+4:], ebcdicPad(devtype, 6))
		copy(b[off+10:], ebcdicPad(model, 3))
		copy(b[off+13:], ebcdicPad("IBM", 3))
		copy(b[off+16:], ebcdicPad("02", 2))
		copy(b[off+18:], ebcdicPad(serial, 12))
	}
	ned(0, 0xdc010100, "003390", "003")
	be.PutUint16(b[30:], d.devno) // device tag: unit address
	ned(32, 0xd4020000, "003990", "006")
	ned(64, 0xd0000000, "003990", "006")
	b[95] = byte(d.devno >> 8) // storage director tag
	ned(96, 0xf0000001, "003990", "   ")
	b[224] = 0x80                            // general NEQ
	be.PutUint16(b[232:], 0x0100|d.devno>>8) // subsystem ID
	b[235] = byte(d.devno)                   // unit address
	b[241] = 0x80                            // interface protocol
	b[243] = byte(d.devno)                   // logical device address
	return b
}

func ebcdicPad(s string, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = 0x40
	}
	for i := 0; i < len(s) && i < n; i++ {
		out[i] = asciiToEBCDIC[s[i]]
	}
	return out
}
