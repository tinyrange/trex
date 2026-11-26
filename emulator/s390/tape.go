package s390

import (
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/tinyrange/trex/archive/simh"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

// Tape3420 is a 3420 magnetic tape drive with a mounted AWS or SIMH image. The
// image is indexed when mounted; written blocks replace the tape from the
// current position in memory, and the image is never modified.
type Tape3420 struct {
	blocks           []tapeBlock
	pos              int // index of the next block
	unloaded         bool
	sense            [24]byte
	pastLoadPoint    bool // the 2401 can move past the load point before block 0
	lastCommand      byte // used by the 2803 while tape motion holds the control unit
	sevenTrack       bool // a 2401 with a seven-track head
	sevenMode        byte // 2803 density, redundancy and conversion mode
	dualDensity      bool
	peOnly           bool
	transportModel   uint8 // 0 uses the original Model 2 transport speed
	modeCompatible   bool  // Model 1–3 attached to a Model 2 tape control
	goInhibitUntil   uint64
	readMotionEnd    uint64
	goDelay          time.Duration
	writePE          bool
	transferPE       bool
	eraseDensity     int   // load-point erase establishes density before the first block
	noConverter      bool  // the optional seven-track data converter is absent
	reelEOT          int64 // 2401 reflective marker measured in 800-bpi frames; 0 means unspecified
	reelPosition     int64
	blankTravel      int64 // head offset within the gap before the next block
	tapeIndicate     bool
	fileProtected    bool
	writeCheckRecord int // zero-based record slot on the mounted reel
	writeChecks      int // remaining injected write data checks

	manual           bool // operator RESET with a threaded reel
	readyArmed       bool // selected by the channel while in manual control
	backward         bool
	writeMode        bool
	turnaround       time.Duration
	loadPointDelay   time.Duration
	unloadUntil      uint64
	reload           byte // zero: no request, one: no ring, two: ring inserted
	readyEnd         bool
	rewindDisconnect uint64

	chanT, devT time.Duration // timing of the last command (CommandTiming)
}

// Drive timing, of the order of a 3420 Model 8: 6250 bpi at 200 in/s, and
// start/stop plus inter-block gap time. Sense moves 24 bytes.
const (
	tapeByte    = 800 * time.Nanosecond
	tapeStart   = time.Millisecond
	tapeControl = 20 * time.Microsecond
)

// CommandTiming implements Timed. Reads and writes hold the channel until
// the block has passed (channel end and device end together). Motion and
// tape-mark commands present channel end in the initial status and device
// end when the motion is complete. Mode sets, no-operation and commands
// rejected at initiation are immediate.
func (t *Tape3420) CommandTiming(cmd byte, n int) (time.Duration, time.Duration) {
	return t.chanT, t.devT
}

// motion sets the timing of a motion command over n bytes of tape.
func (t *Tape3420) motion(n int) { t.chanT, t.devT = 0, tapeStart+time.Duration(n)*tapeByte }

// transfer sets the timing of a data transfer of n bytes.
func (t *Tape3420) transfer(n int) { t.chanT, t.devT = tapeStart+time.Duration(n)*tapeByte, 0 }

func (t *Tape3420) writeRecord(data []byte) {
	t.blocks = append(t.blocks[:t.pos], tapeBlock{data: slices.Clone(data), n: len(data)})
	t.pos++
}

// tapeBlock is a data block or (data == nil, mark) a tape mark.
type tapeBlock struct {
	src          storage.Reader
	off          int64
	n            int
	data         []byte // written blocks
	density      int    // recorded frames per inch, zero for untagged images
	mark         bool
	bad          bool // recovered SIMH record with a recorded data error
	framingError string
	fragmented   []tapeFragment
	reelEnd      int64 // physical position following this block and its gap
	leadIn       int64 // extra erased tape before this block, in 800-bpi frames
	lrcDelta     byte  // seven-track frames missing from the recorded check character
}

type tapeFragment struct {
	off int64
	n   int
}

// MountSIMH indexes a SIMH tape directly. Private metadata and erase gaps do
// not appear as guest records; tape marks and recorded data errors are retained.
// A positionable record with a mismatched trailer causes a data check when read;
// mounting it does not pretend that later damaged media was accessed during IPL.
func MountSIMH(src storage.Reader) (*Tape3420, error) {
	records, err := simh.Index(adapter.File(src), 1000000)
	if err != nil {
		return nil, err
	}
	t := &Tape3420{}
	for _, r := range records {
		if r.TapeMark {
			t.blocks = append(t.blocks, tapeBlock{mark: true})
		} else if r.Data != nil && (r.Class == 0 || r.Class == 8) {
			t.blocks = append(t.blocks, tapeBlock{src: r.Data, n: int(r.Data.Size()), bad: r.Bad, framingError: r.FramingError})
		}
	}
	return t, nil
}

// AWS block header flags.
const (
	awsNewRecord = 0x80
	awsTapeMark  = 0x40
	awsEndRecord = 0x20
)

// MountAWS indexes an AWS tape image: each block is preceded by a 6-byte
// header holding the little-endian lengths of this and the previous chunk
// and flags marking record start, record end and tape marks.
func MountAWS(src storage.Reader) (*Tape3420, error) {
	t := &Tape3420{}
	var h [6]byte
	var cur *tapeBlock
	for off := int64(0); off < src.Size(); {
		if _, err := src.ReadAt(h[:], off); err != nil && err != io.EOF {
			return nil, fmt.Errorf("aws: header at %d: %w", off, err)
		}
		n := int(binary.LittleEndian.Uint16(h[0:]))
		flags := h[4]
		off += 6
		if flags&awsTapeMark != 0 {
			t.blocks = append(t.blocks, tapeBlock{mark: true})
			cur = nil
			continue
		}
		if off+int64(n) > src.Size() {
			return nil, fmt.Errorf("aws: block at %d overruns the image", off-6)
		}
		if flags&awsNewRecord != 0 || cur == nil {
			t.blocks = append(t.blocks, tapeBlock{src: src, off: off, n: n})
			cur = &t.blocks[len(t.blocks)-1]
		} else {
			if cur.fragmented == nil {
				cur.fragmented = []tapeFragment{{cur.off, cur.n}}
			}
			cur.fragmented = append(cur.fragmented, tapeFragment{off, n})
			cur.n += n
		}
		if flags&awsEndRecord != 0 {
			cur = nil
		}
		off += int64(n)
	}
	return t, nil
}

func (b *tapeBlock) bytes() ([]byte, error) {
	if b.framingError != "" {
		return nil, fmt.Errorf("%s", b.framingError)
	}
	if b.data != nil || b.src == nil {
		return b.data, nil
	}
	out := make([]byte, 0, b.n)
	frags := b.fragmented
	if frags == nil {
		frags = []tapeFragment{{b.off, b.n}}
	}
	for _, f := range frags {
		p := make([]byte, f.n)
		if _, err := b.src.ReadAt(p, f.off); err != nil && err != io.EOF {
			return nil, err
		}
		out = append(out, p...)
	}
	return out, nil
}

func (t *Tape3420) SenseID() []byte { return nil }
func (t *Tape3420) Reset()          {}

func (t *Tape3420) check(b0, b1 byte) ([]byte, int, byte) {
	t.sense = [24]byte{}
	t.sense[0], t.sense[1] = b0, b1
	t.status()
	return nil, 0, usCE | usDE | usUnitCheck
}

// status sets the drive-state sense bits: ready, at load point.
func (t *Tape3420) status() {
	if !t.unloaded {
		t.sense[1] |= 0x40 // tape unit ready (TU status A)
	}
	if t.pos == 0 && !t.unloaded {
		t.sense[1] |= 0x08 // load point
	}
}

func (t *Tape3420) Exec(cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	ok := byte(usCE | usDE)
	t.chanT, t.devT = 0, 0
	if cmd == 0x04 { // sense
		t.chanT = tapeControl
		t.status()
		s := t.sense
		t.sense = [24]byte{}
		return s[:], 0, ok
	}
	if cmd == 0x03 { // no-operation
		return nil, 0, ok
	}
	if t.unloaded {
		return t.check(senseIntervReq, 0)
	}
	switch cmd {
	case 0x02, 0x0c: // read forward / backward
		var b *tapeBlock
		if cmd == 0x0c {
			if t.pos == 0 {
				return t.check(0, 0)
			}
			t.pos--
			b = &t.blocks[t.pos]
		} else {
			if t.pos >= len(t.blocks) {
				return t.check(0, 0x20)
			}
			b = &t.blocks[t.pos]
			t.pos++
		}
		t.transfer(b.n)
		if b.mark {
			return nil, 0, ok | usUnitExcept
		}
		p, err := b.bytes()
		if err != nil {
			_, _, status := t.check(senseDataCheck, 0)
			return nil, 0, status
		}
		if cmd == 0x0c {
			// Return bytes in transfer order. The channel decrements the storage
			// address; do not reverse the immutable source or a written overlay.
			p = slices.Clone(p)
			slices.Reverse(p)
		}
		if b.bad {
			_, _, status := t.check(senseDataCheck, 0)
			return p, 0, status
		}
		return p, 0, ok
	case 0x01: // write
		t.writeRecord(data)
		t.transfer(len(data))
		return nil, len(data), ok
	case 0x1f: // write tape mark
		t.blocks = append(t.blocks[:t.pos], tapeBlock{mark: true})
		t.pos++
		t.motion(0)
		return nil, 0, ok
	case 0x07: // rewind
		t.pos = 0
		t.motion(0)
		return nil, 0, ok
	case 0x0f: // rewind and unload
		t.pos = 0
		t.unloaded = true
		t.motion(0)
		return nil, 0, ok
	case 0x37: // forward space block
		if t.pos >= len(t.blocks) {
			return t.check(0, 0x20)
		}
		t.pos++
		t.motion(t.blocks[t.pos-1].n)
		if t.blocks[t.pos-1].mark {
			return nil, 0, ok | usUnitExcept
		}
		return nil, 0, ok
	case 0x27: // backspace block
		if t.pos == 0 {
			return t.check(0, 0)
		}
		t.pos--
		t.motion(t.blocks[t.pos].n)
		if t.blocks[t.pos].mark {
			return nil, 0, ok | usUnitExcept
		}
		return nil, 0, ok
	case 0x3f: // forward space file
		start := t.pos
		n := 0
		for t.pos < len(t.blocks) {
			t.pos++
			n += t.blocks[t.pos-1].n
			if t.blocks[t.pos-1].mark {
				t.motion(n)
				return nil, 0, ok
			}
		}
		if t.pos != start {
			t.motion(n)
		}
		return t.check(0, 0x20)
	case 0x2f: // backspace file
		n := 0
		for t.pos > 0 {
			t.pos--
			n += t.blocks[t.pos].n
			if t.blocks[t.pos].mark {
				break
			}
		}
		t.motion(n)
		return nil, 0, ok
	case 0x17: // erase gap
		t.motion(0)
		return nil, 0, ok
	case 0x0b, 0x13, 0x1b, 0x23, 0x2b, 0x33, 0x3b, 0x43, 0x4b, 0x53, 0x5b, 0x63, 0x6b, 0x73, 0x7b,
		0x93, 0x9b, 0xa3, 0xab, 0xb3, 0xbb, 0xc3, 0xcb, 0xd3, 0xdb, 0xe3, 0xeb, 0xf3, 0xfb: // mode set
		return nil, 0, ok
	}
	return t.check(senseCmdReject, 0)
}
