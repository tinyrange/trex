package ckd

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"runtime"
	"sync"
)

// TrackSet is a volume whose tracks are either held (with records) or null.
type TrackSet interface {
	Tracks() uint32
	Holds(track uint32) bool
	Track(track uint32) ([]Record, error)
}

// CompressedImage is a CKD_C370 image built in memory: the device header,
// the compressed-device header, the level-1 table, every held track as a
// zlib-compressed track image, and the level-2 tables. Null tracks have
// null level-2 entries (format 0: record zero and an end-of-file record one)
// and level-2 groups without a held track have no table. It reads as a
// file, so it can be written out or opened again with OpenCompressed.
type CompressedImage struct {
	head   []byte // device and compressed-device headers and the level-1 table
	tracks [][]byte
	offs   []int64  // image offset of each stored track (0 if null)
	stored []uint32 // the stored tracks, in image order
	l2     map[uint32][]byte
	l2off  map[uint32]int64
	l2keys []uint32
	size   int64
	Held   uint32
}

// Compress builds a CKD_C370 image of the tracks. header is the volume's
// 512-byte CKD_P370 device header (geometry and device code); part fields
// are cleared, since the image holds the whole volume.
func Compress(set TrackSet, header []byte, heads, trackSize uint32) (*CompressedImage, error) {
	if len(header) < 512 || string(header[:8]) != "CKD_P370" {
		return nil, fmt.Errorf("cckd write: a CKD_P370 device header is required")
	}
	n := set.Tracks()
	if heads == 0 || n%heads != 0 {
		return nil, fmt.Errorf("cckd write: %d tracks are not whole cylinders of %d", n, heads)
	}
	cyls := n / heads
	l1n := (n + cckdL2Entries - 1) / cckdL2Entries
	img := &CompressedImage{tracks: make([][]byte, n), offs: make([]int64, n), l2: map[uint32][]byte{}, l2off: map[uint32]int64{}}

	// Read the held tracks in order (sources need not be safe for
	// concurrent use) and compress them in parallel.
	type job struct {
		t    uint32
		recs []Record
	}
	jobs := make(chan job, 64)
	errs := make(chan error, 1)
	fail := func(err error) {
		select {
		case errs <- err:
		default:
		}
	}
	var wg sync.WaitGroup
	for w := 0; w < runtime.GOMAXPROCS(0); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var buf bytes.Buffer
			for j := range jobs {
				b, err := storedTrack(&buf, j.t, heads, trackSize, j.recs)
				if err != nil {
					fail(fmt.Errorf("cckd write: track %d: %w", j.t, err))
					continue
				}
				img.tracks[j.t] = b
			}
		}()
	}
	var readErr error
	for t := uint32(0); t < n && readErr == nil; t++ {
		if !set.Holds(t) {
			continue
		}
		recs, err := set.Track(t)
		if err != nil {
			readErr = fmt.Errorf("cckd write: track %d: %w", t, err)
			break
		}
		jobs <- job{t, recs}
		img.Held++
	}
	close(jobs)
	wg.Wait()
	if readErr != nil {
		return nil, readErr
	}
	select {
	case err := <-errs:
		return nil, err
	default:
	}

	// Layout: headers, level-1 table, track images, level-2 tables.
	pos := int64(1024 + 4*l1n)
	for t := uint32(0); t < n; t++ {
		if img.tracks[t] != nil {
			img.offs[t] = pos
			img.stored = append(img.stored, t)
			pos += int64(len(img.tracks[t]))
		}
	}
	for g := uint32(0); g < l1n; g++ {
		var tab []byte
		for i := uint32(0); i < cckdL2Entries; i++ {
			t := g*cckdL2Entries + i
			if t >= n || img.tracks[t] == nil {
				continue
			}
			if tab == nil {
				tab = make([]byte, 8*cckdL2Entries)
			}
			if img.offs[t] > 0xffffffff || len(img.tracks[t]) > 0xffff {
				return nil, fmt.Errorf("cckd write: image too large for 32-bit offsets")
			}
			e := tab[8*i:]
			le.PutUint32(e, uint32(img.offs[t]))
			le.PutUint16(e[4:], uint16(len(img.tracks[t])))
			le.PutUint16(e[6:], uint16(len(img.tracks[t])))
		}
		if tab != nil {
			img.l2[g] = tab
			img.l2off[g] = pos
			img.l2keys = append(img.l2keys, g)
			pos += int64(len(tab))
		}
	}
	if pos > 0xffffffff {
		return nil, fmt.Errorf("cckd write: image too large for 32-bit offsets")
	}
	img.size = pos
	head := make([]byte, 1024+4*l1n)
	copy(head, header[:512])
	copy(head[:8], "CKD_C370")
	head[17], head[18], head[19] = 0, 0, 0 // one file holds every cylinder
	ch := head[512:]
	ch[0], ch[1], ch[2] = 0, 3, 1 // version 0.3.1, little endian
	le.PutUint32(ch[4:], l1n)
	le.PutUint32(ch[8:], cckdL2Entries)
	le.PutUint32(ch[12:], uint32(pos)) // file size
	le.PutUint32(ch[16:], uint32(pos)) // used
	le.PutUint32(ch[40:], cyls)
	ch[44] = 0 // null tracks hold record zero and an end-of-file record
	for g, off := range img.l2off {
		le.PutUint32(head[1024+4*g:], uint32(off))
	}
	img.head = head
	return img, nil
}

// storedTrack is a compressed track image: compression byte 1 (zlib), the
// physical CCHH, then the compressed records and end-of-track marker.
func storedTrack(buf *bytes.Buffer, t, heads, trackSize uint32, recs []Record) ([]byte, error) {
	buf.Reset()
	for _, r := range recs {
		if len(r.Key) > 255 || len(r.Data) > 0xffff {
			return nil, fmt.Errorf("record %d too long", r.Number)
		}
		var c [8]byte
		be.PutUint16(c[0:], r.Cylinder)
		be.PutUint16(c[2:], r.Head)
		c[4], c[5] = r.Number, byte(len(r.Key))
		be.PutUint16(c[6:], uint16(len(r.Data)))
		buf.Write(c[:])
		buf.Write(r.Key)
		buf.Write(r.Data)
	}
	buf.Write([]byte{255, 255, 255, 255, 255, 255, 255, 255})
	if 5+buf.Len() > int(trackSize) {
		return nil, fmt.Errorf("track image of %d bytes exceeds the track size %d", 5+buf.Len(), trackSize)
	}
	var out bytes.Buffer
	out.Write([]byte{1, byte(t / heads >> 8), byte(t / heads), byte(t % heads >> 8), byte(t % heads)})
	z, err := zlib.NewWriterLevel(&out, zlib.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := z.Write(buf.Bytes()); err != nil {
		return nil, err
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	return bytes.Clone(out.Bytes()), nil
}

// StoredBytes is the stored size of a track's image (0 for a null track).
func (c *CompressedImage) StoredBytes(t uint32) int {
	if int(t) >= len(c.tracks) {
		return 0
	}
	return len(c.tracks[t])
}

// Size is the image's length in bytes.
func (c *CompressedImage) Size() int64 { return c.size }

// ReadAt reads the image.
func (c *CompressedImage) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("cckd image: negative offset")
	}
	n := 0
	for n < len(p) {
		pos := off + int64(n)
		if pos >= c.size {
			return n, io.EOF
		}
		seg, base := c.segment(pos)
		n += copy(p[n:], seg[pos-base:])
	}
	return n, nil
}

// segment finds the stored piece holding pos.
func (c *CompressedImage) segment(pos int64) ([]byte, int64) {
	if pos < int64(len(c.head)) {
		return c.head, 0
	}
	if len(c.l2keys) > 0 && pos >= c.l2off[c.l2keys[0]] {
		lo, hi := 0, len(c.l2keys)
		for hi-lo > 1 {
			mid := (lo + hi) / 2
			if c.l2off[c.l2keys[mid]] <= pos {
				lo = mid
			} else {
				hi = mid
			}
		}
		g := c.l2keys[lo]
		return c.l2[g], c.l2off[g]
	}
	lo, hi := 0, len(c.stored)
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		if c.offs[c.stored[mid]] <= pos {
			lo = mid
		} else {
			hi = mid
		}
	}
	t := c.stored[lo]
	return c.tracks[t], c.offs[t]
}
