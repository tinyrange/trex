package ckd

import (
	"fmt"
	"io"
)

// Image is an immutable, uncompressed CKD_P370 file built from record lists.
// Only populated tracks occupy memory; unspecified tracks contain R0 and an
// empty R1. ReadAt synthesizes home addresses and zero padding without allocating
// the full volume, and is safe for concurrent readers.
type Image struct {
	header                  [512]byte
	tracks                  map[uint32][]byte
	heads, trackSize, count uint32
}

// BuildImage constructs a single-part CKD_P370 file. Geometry is explicit: it
// does not guess device capacities or initialize a VOL1 label, VTOC or OS data.
// Record count addresses are preserved verbatim; home addresses follow physical
// track positions. All input records are copied before returning.
func BuildImage(cylinders, heads, trackSize uint32, device byte, tracks map[uint32][]Record) (*Image, error) {
	if cylinders == 0 || cylinders > 65536 || heads == 0 || heads > 256 || trackSize < 37 || trackSize > 1<<20 {
		return nil, fmt.Errorf("ckd image: invalid geometry %d cylinders, %d heads, %d bytes/track", cylinders, heads, trackSize)
	}
	img := &Image{heads: heads, trackSize: trackSize, count: cylinders * heads, tracks: make(map[uint32][]byte, len(tracks))}
	copy(img.header[:], "CKD_P370")
	le.PutUint32(img.header[8:], heads)
	le.PutUint32(img.header[12:], trackSize)
	img.header[16] = device
	for t, recs := range tracks {
		if t >= img.count {
			return nil, fmt.Errorf("ckd image: track %d outside volume", t)
		}
		used := uint64(13)
		for _, r := range recs {
			if len(r.Key) > 255 || len(r.Data) > 65535 {
				return nil, fmt.Errorf("ckd image: track %d record %d too long", t, r.Number)
			}
			used += 8 + uint64(len(r.Key)) + uint64(len(r.Data))
			if used > uint64(trackSize) {
				return nil, fmt.Errorf("ckd image: track %d exceeds %d bytes", t, trackSize)
			}
		}
		b := make([]byte, int(used))
		be.PutUint16(b[1:], uint16(t/heads))
		be.PutUint16(b[3:], uint16(t%heads))
		pos := 5
		for _, r := range recs {
			be.PutUint16(b[pos:], r.Cylinder)
			be.PutUint16(b[pos+2:], r.Head)
			b[pos+4], b[pos+5] = r.Number, byte(len(r.Key))
			be.PutUint16(b[pos+6:], uint16(len(r.Data)))
			copy(b[pos+8:], r.Key)
			copy(b[pos+8+len(r.Key):], r.Data)
			pos += 8 + len(r.Key) + len(r.Data)
		}
		for i := pos; i < pos+8; i++ {
			b[i] = 255
		}
		img.tracks[t] = b
	}
	return img, nil
}

func (img *Image) Size() int64 { return 512 + int64(img.count)*int64(img.trackSize) }

func (img *Image) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ckd image: negative read offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= img.Size() {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && off < img.Size() {
		if off < 512 {
			k := copy(p[n:], img.header[off:])
			off += int64(k)
			n += k
			continue
		}
		t := uint32((off - 512) / int64(img.trackSize))
		at := int((off - 512) % int64(img.trackSize))
		size := min(len(p)-n, int(img.trackSize)-at)
		dst := p[n : n+size]
		clear(dst)
		b, ok := img.tracks[t]
		var blank [37]byte
		if !ok {
			cc, hh := uint16(t/img.heads), uint16(t%img.heads)
			be.PutUint16(blank[1:], cc)
			be.PutUint16(blank[3:], hh)
			be.PutUint16(blank[5:], cc)
			be.PutUint16(blank[7:], hh)
			be.PutUint16(blank[11:], 8)
			be.PutUint16(blank[21:], cc)
			be.PutUint16(blank[23:], hh)
			blank[25] = 1
			for i := 29; i < 37; i++ {
				blank[i] = 255
			}
			b = blank[:]
		}
		if at < len(b) {
			copy(dst, b[at:])
		}
		off += int64(size)
		n += size
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
