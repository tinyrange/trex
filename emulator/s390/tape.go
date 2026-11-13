package s390

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

// Tape3420 is a 3420 magnetic tape drive with a mounted AWS tape image. The
// image is indexed when mounted; written blocks replace the tape from the
// current position in memory, and the image is never modified.
type Tape3420 struct {
	blocks   []tapeBlock
	pos      int // index of the next block
	unloaded bool
	sense    [24]byte
}

// tapeBlock is a data block or (data == nil, mark) a tape mark.
type tapeBlock struct {
	src        storage.Reader
	off        int64
	n          int
	data       []byte // written blocks
	mark       bool
	fragmented []tapeFragment
}

type tapeFragment struct {
	off int64
	n   int
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
	if cmd == 0x04 { // sense
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
	case 0x02: // read forward
		if t.pos >= len(t.blocks) {
			return t.check(0, 0x20) // end of data: no tape-mark to stop at
		}
		b := &t.blocks[t.pos]
		t.pos++
		if b.mark {
			return nil, 0, ok | usUnitExcept
		}
		p, err := b.bytes()
		if err != nil {
			return t.check(senseDataCheck, 0)
		}
		return p, 0, ok
	case 0x01: // write
		t.blocks = append(t.blocks[:t.pos], tapeBlock{data: append([]byte(nil), data...)})
		t.pos++
		return nil, len(data), ok
	case 0x1f: // write tape mark
		t.blocks = append(t.blocks[:t.pos], tapeBlock{mark: true})
		t.pos++
		return nil, 0, ok
	case 0x07: // rewind
		t.pos = 0
		return nil, 0, ok
	case 0x0f: // rewind and unload
		t.pos = 0
		t.unloaded = true
		return nil, 0, ok
	case 0x37: // forward space block
		if t.pos >= len(t.blocks) {
			return t.check(0, 0x20)
		}
		t.pos++
		if t.blocks[t.pos-1].mark {
			return nil, 0, ok | usUnitExcept
		}
		return nil, 0, ok
	case 0x27: // backspace block
		if t.pos == 0 {
			return t.check(0, 0)
		}
		t.pos--
		if t.blocks[t.pos].mark {
			return nil, 0, ok | usUnitExcept
		}
		return nil, 0, ok
	case 0x3f: // forward space file
		for t.pos < len(t.blocks) {
			t.pos++
			if t.blocks[t.pos-1].mark {
				return nil, 0, ok
			}
		}
		return t.check(0, 0x20)
	case 0x2f: // backspace file
		for t.pos > 0 {
			t.pos--
			if t.blocks[t.pos].mark {
				return nil, 0, ok
			}
		}
		return nil, 0, ok
	case 0x17: // erase gap
		return nil, 0, ok
	case 0x0b, 0x13, 0x1b, 0x23, 0x2b, 0x33, 0x3b, 0x43, 0x4b, 0x53, 0x5b, 0x63, 0x6b, 0x73, 0x7b,
		0x93, 0x9b, 0xa3, 0xab, 0xb3, 0xbb, 0xc3, 0xcb, 0xd3, 0xdb, 0xe3, 0xeb, 0xf3, 0xfb: // mode set
		return nil, 0, ok
	}
	return t.check(senseCmdReject, 0)
}
