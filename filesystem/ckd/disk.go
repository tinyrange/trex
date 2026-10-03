// Package ckd reads uncompressed CKD_P370 disk images through portable readers.
// Implemented independently from observed IBM distribution media; no GPL source
// was consulted or used. See README.md for provenance and supported scope.
package ckd

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

var be = binary.BigEndian
var le = binary.LittleEndian

type Disk struct {
	Source    storage.Reader
	Heads     uint32
	TrackSize uint32
	Device    byte
}

// Record preserves the key and data separately, including record zero and EOF
// records. Count-field addresses need not equal the physical track address;
// preserve them verbatim. Offset is the absolute count-field image offset.
type Record struct {
	Cylinder, Head uint16
	Number         byte
	Offset         int64
	Key, Data      []byte
}

type Stats struct{ Tracks, Records, DataBytes, KeyBytes, ImageBytes int64 }

func Open(source storage.Reader) (*Disk, error) {
	if source == nil {
		return nil, fmt.Errorf("ckd: nil source")
	}
	var h [512]byte
	if _, err := io.ReadFull(io.NewSectionReader(source, 0, 512), h[:]); err != nil {
		return nil, fmt.Errorf("ckd header: %w", err)
	}
	if string(h[:8]) != "CKD_P370" {
		return nil, fmt.Errorf("ckd: unsupported signature %q", h[:8])
	}
	d := &Disk{Source: source, Heads: le.Uint32(h[8:12]), TrackSize: le.Uint32(h[12:16]), Device: h[16]}
	if d.Heads == 0 || d.Heads > 256 || d.TrackSize < 29 || d.TrackSize > 1<<20 {
		return nil, fmt.Errorf("ckd: invalid geometry %d heads, %d bytes/track", d.Heads, d.TrackSize)
	}
	return d, nil
}

func (d *Disk) Track(track uint32) ([]Record, error) {
	if track/d.Heads > 65535 {
		return nil, fmt.Errorf("ckd: track address out of range")
	}
	b := make([]byte, d.TrackSize)
	off := int64(512) + int64(track)*int64(d.TrackSize)
	n, err := d.Source.ReadAt(b, off)
	if n != len(b) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("ckd track %d (%d bytes): %w", track, n, err)
	}
	if err != nil && err != io.EOF {
		return nil, err
	}
	return d.parseTrack(track, b, off)
}

func (d *Disk) parseTrack(track uint32, b []byte, off int64) ([]Record, error) {
	c, h := uint16(track/d.Heads), uint16(track%d.Heads)
	if b[0] != 0 || be.Uint16(b[1:3]) != c || be.Uint16(b[3:5]) != h {
		return nil, fmt.Errorf("ckd track %d: invalid home address %x", track, b[:5])
	}
	var out []Record
	for pos := 5; pos+8 <= len(b); {
		count := b[pos : pos+8]
		if bytes.Equal(count, []byte{255, 255, 255, 255, 255, 255, 255, 255}) {
			return out, nil
		}
		kl, dl := int(count[5]), int(be.Uint16(count[6:8]))
		if pos+8+kl+dl > len(b) {
			return nil, fmt.Errorf("ckd track %d offset %d: invalid record count %x", track, pos, count)
		}
		out = append(out, Record{be.Uint16(count[:2]), be.Uint16(count[2:4]), count[4], off + int64(pos), b[pos+8 : pos+8+kl], b[pos+8+kl : pos+8+kl+dl]})
		pos += 8 + kl + dl
	}
	return nil, fmt.Errorf("ckd track %d: missing end marker", track)
}

// Walk reads every track in ascending order, including free space, and probes
// the exact EOF. This validates gzip trailers when Source is a gzip reader.
// Record slices are borrowed until the next callback; copy bytes to retain them.
// The walk itself retains only one track.
func (d *Disk) Walk(ctx context.Context, visit func(uint32, []Record) error) (Stats, error) {
	var s Stats
	b := make([]byte, d.TrackSize)
	for t := uint32(0); ; t++ {
		if err := ctx.Err(); err != nil {
			return s, err
		}
		off := int64(512) + int64(t)*int64(d.TrackSize)
		n, err := d.Source.ReadAt(b, off)
		if n == 0 && err == io.EOF {
			if t == 0 || t%d.Heads != 0 {
				return s, fmt.Errorf("ckd: incomplete cylinder at EOF after %d tracks", t)
			}
			s.ImageBytes = off
			return s, nil
		}
		if n != len(b) || (err != nil && err != io.EOF) {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return s, fmt.Errorf("ckd track %d: short or failed read (%d): %w", t, n, err)
		}
		if t/d.Heads > 65535 {
			return s, fmt.Errorf("ckd: too many cylinders")
		}
		records, err := d.parseTrack(t, b, off)
		if err != nil {
			return s, err
		}
		s.Tracks++
		s.Records += int64(len(records))
		for _, r := range records {
			s.DataBytes += int64(len(r.Data))
			s.KeyBytes += int64(len(r.Key))
		}
		if visit != nil {
			if err := visit(t, records); err != nil {
				return s, err
			}
		}
	}
}
