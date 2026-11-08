package ckd

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/tinyrange/trex/storage"
)

// Compressed CKD_C370 base images: a 512-byte device header, a 512-byte
// compressed-device header, a level-1 table of level-2 table offsets, and
// level-2 entries (offset, length, allocated size) addressing one stored
// track image each. A stored track begins with a compression byte and the
// physical CCHH; the remainder is either raw or a zlib stream of the records
// that follow the home address. Layout decoded from observed z/VM ADCD media
// and the published Hercules CCKD format description; no implementation
// source was consulted.

const cckdL2Entries = 256

// Compressed exposes a CKD_C370 base image as an equivalent uncompressed
// CKD_P370 image: the same device header (with the P370 signature), followed
// by every track padded to the declared track size. Tracks are decoded on
// demand; only the most recently decoded track is retained.
type Compressed struct {
	source    storage.Reader
	order     binary.ByteOrder
	header    [512]byte
	trackSize int64
	tracks    uint32
	heads     uint32
	nullFmt   byte
	l1        []uint32

	mu    sync.Mutex
	l2    map[uint32][]byte
	track int64
	buf   []byte
}

// IsCompressed reports whether the header names a CCKD base image.
func IsCompressed(p []byte) bool { return len(p) >= 8 && string(p[:8]) == "CKD_C370" }

// OpenCompressed validates the device, compressed-device and level-1 headers.
// Missing level-2 tables use the header's null format; null level-2 entries
// carry their own.
// Each track names its own compression. Shadow files (CKD_S370), FBA
// images, bzip2 tracks and null formats other
// than 0 (EOF record) and 1 (record zero only) are rejected explicitly.
func OpenCompressed(source storage.Reader) (*Compressed, error) {
	if source == nil {
		return nil, fmt.Errorf("cckd: nil source")
	}
	var h [1024]byte
	if _, err := io.ReadFull(io.NewSectionReader(source, 0, 1024), h[:]); err != nil {
		return nil, fmt.Errorf("cckd header: %w", err)
	}
	if !IsCompressed(h[:]) {
		return nil, fmt.Errorf("cckd: unsupported signature %q", h[:8])
	}
	c := &Compressed{source: source, order: binary.LittleEndian, track: -1, l2: map[uint32][]byte{}}
	copy(c.header[:], h[:512])
	copy(c.header[:8], "CKD_P370")
	c.heads, c.trackSize = le.Uint32(h[8:12]), int64(le.Uint32(h[12:16]))
	if c.heads == 0 || c.heads > 256 || c.trackSize < 29 || c.trackSize > 1<<20 {
		return nil, fmt.Errorf("cckd: invalid geometry %d heads, %d bytes/track", c.heads, c.trackSize)
	}
	ch := h[512:]
	if ch[0] != 0 {
		return nil, fmt.Errorf("cckd: unsupported version %d.%d.%d", ch[0], ch[1], ch[2])
	}
	if ch[3]&0x02 != 0 {
		c.order = binary.BigEndian
	}
	l1n, l2n := c.order.Uint32(ch[4:8]), c.order.Uint32(ch[8:12])
	cyls := c.order.Uint32(ch[40:44])
	c.nullFmt = ch[44]
	if l2n != cckdL2Entries {
		return nil, fmt.Errorf("cckd: unsupported level-2 table size %d", l2n)
	}
	if cyls == 0 || cyls > 65536 || uint64(cyls)*uint64(c.heads) > uint64(l1n)*cckdL2Entries || l1n > 1<<16 {
		return nil, fmt.Errorf("cckd: %d cylinders do not fit %d level-1 entries", cyls, l1n)
	}
	if c.nullFmt > 1 {
		return nil, fmt.Errorf("cckd: unsupported null track format %d", c.nullFmt)
	}
	c.tracks = cyls * c.heads
	raw := make([]byte, 4*int(l1n))
	if _, err := io.ReadFull(io.NewSectionReader(source, 1024, int64(len(raw))), raw); err != nil {
		return nil, fmt.Errorf("cckd level-1 table: %w", err)
	}
	c.l1 = make([]uint32, l1n)
	for i := range c.l1 {
		c.l1[i] = c.order.Uint32(raw[4*i:])
		if c.l1[i] == 0xffffffff {
			return nil, fmt.Errorf("cckd: level-1 entry %d refers to a shadow base", i)
		}
		if c.l1[i] != 0 && (int64(c.l1[i]) < 1024+int64(len(raw)) || int64(c.l1[i])+8*cckdL2Entries > source.Size()) {
			return nil, fmt.Errorf("cckd: level-1 entry %d offset %d outside image", i, c.l1[i])
		}
	}
	return c, nil
}

// Size is the equivalent uncompressed CKD_P370 image size.
func (c *Compressed) Size() int64 { return 512 + int64(c.tracks)*c.trackSize }

// Tracks is the number of tracks described by the cylinder count.
func (c *Compressed) Tracks() uint32 { return c.tracks }

func (c *Compressed) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("cckd: negative offset")
	}
	n := 0
	for n < len(p) {
		pos := off + int64(n)
		if pos >= c.Size() {
			return n, io.EOF
		}
		if pos < 512 {
			n += copy(p[n:], c.header[pos:])
			continue
		}
		t := (pos - 512) / c.trackSize
		c.mu.Lock()
		b, err := c.loadLocked(uint32(t))
		if err == nil {
			n += copy(p[n:], b[(pos-512)%c.trackSize:])
		}
		c.mu.Unlock()
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (c *Compressed) level2Locked(i uint32) ([]byte, error) {
	if b, ok := c.l2[i]; ok {
		return b, nil
	}
	b := make([]byte, 8*cckdL2Entries)
	if _, err := io.ReadFull(io.NewSectionReader(c.source, int64(c.l1[i]), int64(len(b))), b); err != nil {
		return nil, fmt.Errorf("cckd level-2 table %d: %w", i, err)
	}
	c.l2[i] = b
	return b, nil
}

// loadLocked returns the padded P370 image of track t; it is valid until the
// next load.
func (c *Compressed) loadLocked(t uint32) ([]byte, error) {
	if int64(t) == c.track {
		return c.buf, nil
	}
	if c.buf == nil {
		c.buf = make([]byte, c.trackSize)
	}
	c.track = -1
	clear(c.buf)
	cc, hh := uint16(t/c.heads), uint16(t%c.heads)
	var pos uint32
	var length uint16
	format := c.nullFmt
	if l1 := c.l1[t/cckdL2Entries]; l1 != 0 {
		l2, err := c.level2Locked(t / cckdL2Entries)
		if err != nil {
			return nil, err
		}
		e := l2[8*(t%cckdL2Entries):]
		pos, length = c.order.Uint32(e), c.order.Uint16(e[4:])
		size := c.order.Uint16(e[6:])
		if size < length {
			return nil, fmt.Errorf("cckd track %d: length %d exceeds allocation %d", t, length, size)
		}
		if pos == 0 {
			// A null level-2 entry records its own null format in both
			// length and size.
			if length > 1 || size != length {
				return nil, fmt.Errorf("cckd track %d: unsupported null entry %d/%d", t, length, size)
			}
			format = byte(length)
		}
	}
	if pos == 0 {
		c.nullTrack(cc, hh, format)
		c.track = int64(t)
		return c.buf, nil
	}
	if length < 5+8 || int64(pos)+int64(length) > c.source.Size() || int64(pos) < 1024+4*int64(len(c.l1)) {
		return nil, fmt.Errorf("cckd track %d: invalid image extent %d+%d", t, pos, length)
	}
	stored := make([]byte, length)
	if _, err := io.ReadFull(io.NewSectionReader(c.source, int64(pos), int64(length)), stored); err != nil {
		return nil, fmt.Errorf("cckd track %d: %w", t, err)
	}
	if be.Uint16(stored[1:3]) != cc || be.Uint16(stored[3:5]) != hh {
		return nil, fmt.Errorf("cckd track %d: stored address %x", t, stored[1:5])
	}
	used := 5
	switch stored[0] {
	case 0:
		if int64(length) > c.trackSize {
			return nil, fmt.Errorf("cckd track %d: image exceeds track size", t)
		}
		used += copy(c.buf[5:], stored[5:])
	case 1:
		src := bytes.NewReader(stored[5:])
		z, err := zlib.NewReader(src)
		if err != nil {
			return nil, fmt.Errorf("cckd track %d: %w", t, err)
		}
		n, err := io.ReadFull(z, c.buf[5:])
		if err == nil {
			// The track is full; the stream must end (and verify) here.
			var one [1]byte
			var m int
			m, err = z.Read(one[:])
			if m != 0 {
				return nil, fmt.Errorf("cckd track %d: decompressed image exceeds track size", t)
			}
		}
		if err != io.ErrUnexpectedEOF && err != io.EOF {
			return nil, fmt.Errorf("cckd track %d: %w", t, err)
		}
		if err := z.Close(); err != nil {
			return nil, fmt.Errorf("cckd track %d: %w", t, err)
		}
		if src.Len() != 0 {
			return nil, fmt.Errorf("cckd track %d: %d bytes after compressed stream", t, src.Len())
		}
		used += n
	default:
		return nil, fmt.Errorf("cckd track %d: unsupported compression %d", t, stored[0])
	}
	if used < 13 || !bytes.Equal(c.buf[used-8:used], []byte{255, 255, 255, 255, 255, 255, 255, 255}) {
		return nil, fmt.Errorf("cckd track %d: image does not end with end-of-track marker", t)
	}
	be.PutUint16(c.buf[1:3], cc)
	be.PutUint16(c.buf[3:5], hh)
	c.track = int64(t)
	return c.buf, nil
}

// nullTrack writes the home address, an 8-byte record zero and, for format 0,
// an end-of-file record one, then the end-of-track marker.
func (c *Compressed) nullTrack(cc, hh uint16, format byte) {
	b := c.buf
	be.PutUint16(b[1:], cc)
	be.PutUint16(b[3:], hh)
	p := 5
	count := func(r byte, dl uint16) {
		be.PutUint16(b[p:], cc)
		be.PutUint16(b[p+2:], hh)
		b[p+4], b[p+5] = r, 0
		be.PutUint16(b[p+6:], dl)
		p += 8 + int(dl)
	}
	count(0, 8)
	if format == 0 {
		count(1, 0)
	}
	copy(b[p:], []byte{255, 255, 255, 255, 255, 255, 255, 255})
}
