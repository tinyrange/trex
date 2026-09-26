// Package mds reads Alcohol Media Descriptor files and their portable companion
// byte sources. Track payloads, audio and subchannels are views, never copies.
package mds

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
	"unicode/utf16"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

type Session struct {
	Number, FirstTrack, LastTrack uint16
	Start, End                    int32
	// TOC retains all twelve-byte Q-channel descriptors, including lead-in.
	TOC    [][]byte
	Tracks []Track
}

type Track struct {
	Number, Mode, Subchannel, ADR, Control byte
	SectorSize                             uint16
	StartLBA, Pregap, Sectors              uint32
	Offset                                 uint64
	Files                                  []string
}

type Image struct {
	Version  [2]byte
	Medium   uint16
	Sessions []Session
}

// Resolver supplies a filename declared by the descriptor. It is deliberately
// independent of host paths. The caller resolves the conventional *.mdf name.
type Resolver func(name string) (storage.Reader, error)

// Bound aggregate metadata work, including repeated references into the same
// descriptor. Per-record size checks alone do not bound a reference graph.
type descriptorReader struct {
	storage.Reader
	remaining int64
}

func (r *descriptorReader) ReadAt(p []byte, off int64) (int, error) {
	if int64(len(p)) > r.remaining {
		return 0, fmt.Errorf("mds: metadata read budget exceeded")
	}
	r.remaining -= int64(len(p))
	return r.Reader.ReadAt(p, off)
}

func read(source storage.Reader, off, size int64) ([]byte, error) {
	if off < 0 || size < 0 || off > source.Size() || size > source.Size()-off {
		return nil, fmt.Errorf("mds: descriptor range outside input")
	}
	b := make([]byte, size)
	_, err := io.ReadFull(io.NewSectionReader(source, off, size), b)
	return b, err
}

// Open parses descriptor metadata without requiring an MDF. Field layouts are
// documented in README.md. No sector scanning or filesystem guessing is used.
func Open(source storage.Reader) (*Image, error) {
	if source == nil {
		return nil, fmt.Errorf("mds: nil descriptor")
	}
	source = &descriptorReader{Reader: source, remaining: 8 << 20}
	h, err := read(source, 0, 88)
	if err != nil {
		return nil, err
	}
	if string(h[:16]) != "MEDIA DESCRIPTOR" {
		return nil, fmt.Errorf("mds: invalid signature")
	}
	if h[16] != 1 {
		return nil, fmt.Errorf("mds: unsupported version %d.%d", h[16], h[17])
	}
	le := binary.LittleEndian
	image := &Image{Version: [2]byte{h[16], h[17]}, Medium: le.Uint16(h[18:])}
	switch image.Medium {
	case 0, 1, 2, 0x10, 0x12:
	default:
		return nil, fmt.Errorf("mds: unsupported medium %#x", image.Medium)
	}
	count, offset := int64(le.Uint16(h[20:])), int64(le.Uint32(h[80:]))
	if count == 0 || count > 99 || offset < 88 {
		return nil, fmt.Errorf("mds: invalid session table")
	}
	seenSessions := map[uint16]bool{}
	seenTracks := map[byte]bool{}
	names := map[[2]uint32]string{}
	references := int64(0)
	for i := int64(0); i < count; i++ {
		s, err := read(source, offset+i*24, 24)
		if err != nil {
			return nil, err
		}
		session := Session{Number: le.Uint16(s[8:]), FirstTrack: le.Uint16(s[12:]), LastTrack: le.Uint16(s[14:]), Start: int32(le.Uint32(s)), End: int32(le.Uint32(s[4:]))}
		if session.Number == 0 || seenSessions[session.Number] || session.FirstTrack == 0 || session.LastTrack > 99 || session.FirstTrack > session.LastTrack || session.End < session.Start || s[11] > s[10] {
			return nil, fmt.Errorf("mds: invalid session geometry")
		}
		seenSessions[session.Number] = true
		tracksOffset := int64(le.Uint32(s[20:]))
		for j := int64(0); j < int64(s[10]); j++ {
			b, err := read(source, tracksOffset+j*80, 80)
			if err != nil {
				return nil, err
			}
			session.TOC = append(session.TOC, bytes.Clone(b[:12]))
			point := b[4]
			if point >= 0xa0 {
				continue
			}
			if point == 0 || uint16(point) < session.FirstTrack || uint16(point) > session.LastTrack || seenTracks[point] {
				return nil, fmt.Errorf("mds: invalid or duplicate track number")
			}
			seenTracks[point] = true
			track := Track{Number: point, Mode: b[0], Subchannel: b[1], ADR: b[2] >> 4, Control: b[2] & 15, SectorSize: le.Uint16(b[16:]), StartLBA: le.Uint32(b[36:]), Offset: le.Uint64(b[40:])}
			if image.Medium == 0x10 || image.Medium == 0x12 {
				track.Sectors = le.Uint32(b[12:])
			} else {
				extra, err := read(source, int64(le.Uint32(b[12:])), 8)
				if err != nil {
					return nil, err
				}
				track.Pregap, track.Sectors = le.Uint32(extra), le.Uint32(extra[4:])
			}
			if track.Sectors == 0 || track.Offset > math.MaxInt64 {
				return nil, fmt.Errorf("mds: invalid track extent")
			}
			if _, _, err := track.layout(); err != nil {
				return nil, err
			}
			files, footer := int64(le.Uint32(b[48:])), int64(le.Uint32(b[52:]))
			if files == 0 || files > 1024 || footer < 88 {
				return nil, fmt.Errorf("mds: invalid companion table")
			}
			references += files
			if references > 65536 {
				return nil, fmt.Errorf("mds: excessive companion references")
			}
			for k := int64(0); k < files; k++ {
				f, err := read(source, footer+k*16, 16)
				if err != nil {
					return nil, err
				}
				key := [2]uint32{le.Uint32(f), le.Uint32(f[4:])}
				name, found := names[key]
				if !found {
					name, err = filename(source, int64(key[0]), key[1])
					if err != nil {
						return nil, err
					}
					names[key] = name
				}
				track.Files = append(track.Files, name)
			}
			session.Tracks = append(session.Tracks, track)
		}
		if len(session.Tracks) != int(session.LastTrack-session.FirstTrack+1) || len(session.Tracks) != int(s[10]-s[11]) {
			return nil, fmt.Errorf("mds: track count disagrees with session")
		}
		image.Sessions = append(image.Sessions, session)
	}
	return image, nil
}

func filename(source storage.Reader, offset int64, wide uint32) (string, error) {
	if wide > 1 || offset < 88 || offset >= source.Size() {
		return "", fmt.Errorf("mds: invalid filename reference")
	}
	width := int64(1 + wide)
	var units []uint16
	for i := int64(0); i < 4096; i += width {
		b, err := read(source, offset+i, width)
		if err != nil {
			return "", err
		}
		u := uint16(b[0])
		if wide == 1 {
			u = binary.LittleEndian.Uint16(b)
		}
		if u == 0 {
			if len(units) == 0 {
				return "", fmt.Errorf("mds: empty filename")
			}
			if wide == 0 {
				b := make([]byte, len(units))
				for i, u := range units {
					b[i] = byte(u)
				}
				return string(b), nil
			}
			for j := 0; j < len(units); j++ {
				u := units[j]
				if u >= 0xd800 && u <= 0xdbff {
					if j+1 == len(units) || units[j+1] < 0xdc00 || units[j+1] > 0xdfff {
						return "", fmt.Errorf("mds: invalid UTF-16 filename")
					}
					j++
				} else if u >= 0xdc00 && u <= 0xdfff {
					return "", fmt.Errorf("mds: invalid UTF-16 filename")
				}
			}
			return string(utf16.Decode(units)), nil
		}
		units = append(units, u)
	}
	return "", fmt.Errorf("mds: unterminated filename")
}

// layout returns payload offset and length within each stored sector.
func (t Track) layout() (int64, int64, error) {
	stride := int64(t.SectorSize)
	if t.Subchannel == 8 {
		stride -= 96
	} else if t.Subchannel != 0 {
		return 0, 0, fmt.Errorf("mds: unsupported subchannel mode %#x", t.Subchannel)
	}
	var offset, size int64
	switch t.Mode {
	case 0xa9, 0xe9:
		size = 2352
	case 2:
		size = 2048
	case 0xaa, 0xea:
		size = 2048
		if stride == 2352 {
			offset = 16
		}
	case 0xab, 0xeb:
		size = 2336
		if stride == 2352 {
			offset = 16
		}
	case 0xac, 0xec:
		size = 2048
		if stride == 2352 {
			offset = 24
		} else if stride == 2336 {
			offset = 8
		}
	case 0xad, 0xed:
		size = 2324
		if stride == 2352 {
			offset = 24
		} else if stride == 2336 {
			offset = 8
		}
	default:
		return 0, 0, fmt.Errorf("mds: unsupported track mode %#x", t.Mode)
	}
	if stride < offset+size || (stride != size && stride != 2352 && stride != 2336) {
		return 0, 0, fmt.Errorf("mds: invalid sector size %d for mode %#x", t.SectorSize, t.Mode)
	}
	return offset, size, nil
}

// TrackReaders separates the stored sectors, logical payload, and (if present)
// interleaved 96-byte P-W subchannels. Pregap is descriptor metadata; no absent
// lead-in sectors are fabricated and no bytes are silently removed.
type TrackReaders struct{ Raw, Data, Subchannel storage.Reader }

func (t Track) Readers(resolve Resolver) (*TrackReaders, error) {
	if resolve == nil {
		return nil, fmt.Errorf("mds: companion resolver required")
	}
	var joined joinedReader
	for index, name := range t.Files {
		r, err := resolve(name)
		if err != nil {
			return nil, fmt.Errorf("mds: companion %q: %w", name, err)
		}
		if r == nil || r.Size() < 0 || r.Size() > math.MaxInt64-joined.size {
			return nil, fmt.Errorf("mds: invalid companion size")
		}
		if index == 0 && t.Offset > uint64(r.Size()) {
			return nil, fmt.Errorf("mds: track offset exceeds first companion")
		}
		joined.sources = append(joined.sources, r)
		joined.size += r.Size()
	}
	size := int64(t.Sectors) * int64(t.SectorSize)
	if t.Offset > uint64(joined.size) || size > joined.size-int64(t.Offset) {
		return nil, fmt.Errorf("mds: track %d exceeds companion data", t.Number)
	}
	off, n, err := t.layout()
	if err != nil {
		return nil, err
	}
	raw := io.NewSectionReader(&joined, int64(t.Offset), size)
	result := &TrackReaders{Raw: raw, Data: &sectorReader{source: raw, stride: int64(t.SectorSize), offset: off, width: n, sectors: int64(t.Sectors)}}
	if t.Subchannel == 8 {
		result.Subchannel = &sectorReader{source: raw, stride: int64(t.SectorSize), offset: int64(t.SectorSize) - 96, width: 96, sectors: int64(t.Sectors)}
	}
	return result, nil
}

type joinedReader struct {
	sources []storage.Reader
	size    int64
}

func (r *joinedReader) Size() int64 { return r.size }
func (r *joinedReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("mds: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	n := 0
	for _, s := range r.sources {
		if off >= s.Size() {
			off -= s.Size()
			continue
		}
		count := min(int64(len(p)), s.Size()-off)
		got, err := s.ReadAt(p[:count], off)
		n += got
		p = p[got:]
		if err != nil && !(err == io.EOF && int64(got) == count) {
			return n, err
		}
		if int64(got) != count {
			return n, io.ErrUnexpectedEOF
		}
		if len(p) == 0 {
			return n, nil
		}
		off = 0
	}
	return n, io.EOF
}

type sectorReader struct {
	source                         storage.Reader
	stride, offset, width, sectors int64
}

func (r *sectorReader) Size() int64 { return r.width * r.sectors }
func (r *sectorReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("mds: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.Size() {
		return 0, io.EOF
	}
	want := len(p)
	p = p[:min(int64(len(p)), r.Size()-off)]
	n := 0
	for len(p) > 0 {
		sector, within := off/r.width, off%r.width
		count := min(int64(len(p)), r.width-within)
		got, err := r.source.ReadAt(p[:count], sector*r.stride+r.offset+within)
		n += got
		off += int64(got)
		p = p[got:]
		if err != nil {
			return n, err
		}
		if int64(got) != count {
			return n, io.ErrUnexpectedEOF
		}
	}
	if n < want {
		return n, io.EOF
	}
	return n, nil
}

func (t Track) Attributes() map[string]any {
	_, width, _ := t.layout()
	return map[string]any{"track": int(t.Number), "mode": int(t.Mode), "subchannel_mode": int(t.Subchannel), "adr": int(t.ADR), "control": int(t.Control), "sector_size": int(t.SectorSize), "logical_sector_size": width, "start_lba": int64(t.StartLBA), "pregap_sectors": int64(t.Pregap), "sectors": int64(t.Sectors), "offset": t.Offset, "files": append([]string(nil), t.Files...)}
}

func (i *Image) View(resolve Resolver) (auto.View, error) {
	var sessions []auto.Entry
	for _, s := range i.Sessions {
		var tracks []auto.Entry
		for _, t := range s.Tracks {
			attrs := t.Attributes()
			attrs["complete"] = resolve != nil
			var payload []auto.Entry
			if resolve != nil {
				r, err := t.Readers(resolve)
				if err != nil {
					return nil, err
				}
				name := "data"
				if t.Mode == 0xa9 || t.Mode == 0xe9 {
					name = "audio"
				}
				payload = []auto.Entry{{Name: name, Kind: "file", Reader: r.Data}, {Name: "raw", Kind: "file", Reader: r.Raw}}
				if r.Subchannel != nil {
					payload = append(payload, auto.Entry{Name: "subchannel", Kind: "file", Reader: r.Subchannel})
				}
			}
			tracks = append(tracks, auto.Entry{Name: fmt.Sprintf("track-%d", t.Number), Kind: "directory", Attributes: attrs, View: auto.ViewFunc(func() ([]auto.Entry, error) { return payload, nil })})
		}
		sessions = append(sessions, auto.Entry{Name: fmt.Sprintf("session-%d", s.Number), Kind: "directory", Attributes: map[string]any{"session": int(s.Number), "start_lba": int64(s.Start), "end_lba": int64(s.End), "first_track": int(s.FirstTrack), "last_track": int(s.LastTrack), "toc": s.TOC}, View: auto.ViewFunc(func() ([]auto.Entry, error) { return tracks, nil })})
	}
	return &auto.DescribedView{Format: "mds", Attributes: map[string]any{"version": fmt.Sprintf("%d.%d", i.Version[0], i.Version[1]), "medium": int(i.Medium), "sessions": len(i.Sessions), "companions_available": resolve != nil}, View: auto.ViewFunc(func() ([]auto.Entry, error) { return sessions, nil })}, nil
}

func safeCompanion(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\:\x00")
}
