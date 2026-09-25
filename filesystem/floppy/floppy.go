// Package floppy decodes DiskDupe, HD-Copy and The Duplicator disk images.
// Decoding is bounded by floppy geometry; source data is never extracted.
package floppy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// ErrMissingTrack means the image did not record the requested track. Its
// contents are unknown, not implicitly zero-filled.
var ErrMissingTrack = errors.New("floppy: omitted track")

const ddiMagic = "IM\x00\x00\x00\x00\x00\x00\x00\x00"
const duplicatorMagic = "Image file of a diskette by THE DUPLICATOR"

type extent struct {
	offset  int64
	data    []byte
	missing bool
	fill    byte
}

// File is an immutable logical sector view. Uncompressed extents borrow source;
// HD-Copy tracks are validated and decoded into bounded in-memory buffers.
type File struct {
	source                          storage.Reader
	format                          string
	cylinders, heads, sectors, unit int
	extents                         []extent
}

func (f *File) Size() int64 { return int64(len(f.extents) * f.unit) }

// ContiguousPrefixSize lets format identification avoid speculative reads into
// omitted tracks. Actual reads of those tracks still return ErrMissingTrack.
func (f *File) ContiguousPrefixSize() int64 {
	for i, e := range f.extents {
		if e.missing {
			return int64(i * f.unit)
		}
	}
	return f.Size()
}
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("floppy: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.Size() {
		return 0, io.EOF
	}
	want := len(p)
	p = p[:min(int64(len(p)), f.Size()-off)]
	n := 0
	for len(p) > 0 {
		index, within := int(off/int64(f.unit)), int(off%int64(f.unit))
		e := f.extents[index]
		if e.missing {
			return n, fmt.Errorf("%w %d in %s", ErrMissingTrack, index, f.format)
		}
		count := min(len(p), f.unit-within)
		switch {
		case e.data != nil:
			copy(p[:count], e.data[within:within+count])
		case e.offset >= 0:
			got, err := f.source.ReadAt(p[:count], e.offset+int64(within))
			if err != nil {
				return n + got, err
			}
			if got != count {
				return n + got, io.ErrUnexpectedEOF
			}
		default:
			for i := range p[:count] {
				p[i] = e.fill
			}
		}
		n += count
		off += int64(count)
		p = p[count:]
	}
	if n < want {
		return n, io.EOF
	}
	return n, nil
}
func read(r storage.Reader, off int64, size int) ([]byte, error) {
	if off < 0 || off > r.Size() || int64(size) > r.Size()-off {
		return nil, io.ErrUnexpectedEOF
	}
	b := make([]byte, size)
	n, e := r.ReadAt(b, off)
	if e != nil {
		return nil, e
	}
	if n != size {
		return nil, io.ErrUnexpectedEOF
	}
	return b, nil
}
func u16(b []byte) int { return int(binary.LittleEndian.Uint16(b)) }
func (f *File) stored(off int64, header int, used *[][2]int64) (extent, error) {
	end := off + int64(f.unit)
	if off < int64(header) || end > f.source.Size() {
		return extent{}, fmt.Errorf("%s: stored extent outside payload", f.format)
	}
	for _, r := range *used {
		if off < r[1] && end > r[0] {
			return extent{}, fmt.Errorf("%s: overlapping stored extents", f.format)
		}
	}
	*used = append(*used, [2]int64{off, end})
	return extent{offset: off}, nil
}

// OpenDiskDupe supports the four PC disk types recorded in DDI track maps.
func OpenDiskDupe(r storage.Reader) (*File, error) {
	h, e := read(r, 0, 11)
	if e != nil {
		return nil, e
	}
	if string(h[:10]) != ddiMagic || h[10] < 1 || h[10] > 4 {
		return nil, fmt.Errorf("diskdupe: invalid header")
	}
	geometry := [5][2]int{{}, {40, 9}, {80, 15}, {80, 9}, {80, 18}}
	g := geometry[h[10]]
	f := &File{source: r, format: "diskdupe", cylinders: g[0], heads: 2, sectors: g[1], unit: g[1] * 512, extents: make([]extent, g[0]*2)}
	header := 100 + len(f.extents)*6
	m, e := read(r, 100, len(f.extents)*6)
	if e != nil {
		return nil, e
	}
	var used [][2]int64
	for i := range f.extents {
		b := m[i*6 : i*6+6]
		if b[0] > 1 || b[2] != 0 || b[3] != 0 || b[4] != 0 {
			return nil, fmt.Errorf("diskdupe: invalid track %d map", i)
		}
		if b[0] == 0 {
			f.extents[i].missing = true
			continue
		}
		f.extents[i], e = f.stored(int64(b[1])*int64(f.unit), header, &used)
		if e != nil {
			return nil, e
		}
	}
	return f, nil
}

// OpenDuplicator supports version 1, including explicitly filled cylinders.
// Cylinder checksums are preserved in the source but are not verified.
func OpenDuplicator(r storage.Reader) (*File, error) {
	h, e := read(r, 0, 96)
	if e != nil {
		return nil, e
	}
	if !bytes.HasPrefix(h, []byte(duplicatorMagic)) || u16(h[64:]) != 1 {
		return nil, fmt.Errorf("duplicator: invalid signature or unsupported version")
	}
	heads, sectors, cyl := u16(h[66:]), u16(h[68:]), u16(h[70:])
	if heads < 1 || heads > 2 || sectors < 1 || sectors > 40 || cyl < 1 || cyl > 84 {
		return nil, fmt.Errorf("duplicator: invalid geometry")
	}
	f := &File{source: r, format: "duplicator", cylinders: cyl, heads: heads, sectors: sectors, unit: heads * sectors * 512, extents: make([]extent, cyl)}
	m, e := read(r, 96, cyl*8)
	if e != nil {
		return nil, e
	}
	var used [][2]int64
	for i := range f.extents {
		b := m[i*8 : i*8+8]
		switch u16(b[2:]) {
		case 0:
			f.extents[i], e = f.stored(int64(u16(b[4:]))*512, 96+cyl*8, &used)
			if e != nil {
				return nil, e
			}
		case 2:
			f.extents[i] = extent{offset: -1, fill: b[6]}
		default:
			return nil, fmt.Errorf("duplicator: invalid cylinder %d flags", i)
		}
	}
	return f, nil
}

func hdCandidate(p []byte) bool {
	if len(p) < 2 {
		return false
	}
	if p[0] == 255 && p[1] == 24 {
		return true
	}
	// There is no standard magic: require geometry and a plausible complete map.
	if len(p) < 166 || p[0] < 37 || p[0] > 81 || p[1] < 8 || p[1] > 40 || p[2] != 1 || p[3] != 1 {
		return false
	}
	for _, v := range p[2:166] {
		if v > 1 {
			return false
		}
	}
	return true
}

// OpenHDCopy supports standard and extended maps and validates every RLE block.
func OpenHDCopy(r storage.Reader) (*File, error) {
	h, e := read(r, 0, 2)
	if e != nil {
		return nil, e
	}
	mapoff, maplen := 2, 164
	last, sectors := int(h[0]), int(h[1])
	if h[0] == 255 && h[1] == 24 {
		h, e = read(r, 0, 16)
		if e != nil {
			return nil, e
		}
		mapoff, maplen = 16, 168
		last, sectors = int(h[14]), int(h[15])
	}
	if last < 37 || (last+1)*2 > maplen || sectors < 8 || sectors > 40 {
		return nil, fmt.Errorf("hdcopy: invalid geometry")
	}
	m, e := read(r, int64(mapoff), maplen)
	if e != nil {
		return nil, e
	}
	for _, v := range m {
		if v > 1 {
			return nil, fmt.Errorf("hdcopy: invalid track map")
		}
	}
	if m[0] != 1 || m[1] != 1 {
		return nil, fmt.Errorf("hdcopy: missing initial tracks")
	}
	f := &File{source: r, format: "hdcopy", cylinders: last + 1, heads: 2, sectors: sectors, unit: sectors * 512, extents: make([]extent, (last+1)*2)}
	pos := int64(mapoff + maplen)
	for i := range f.extents {
		if m[i] == 0 {
			f.extents[i].missing = true
			continue
		}
		h, e = read(r, pos, 3)
		if e != nil {
			return nil, fmt.Errorf("hdcopy track %d: %w", i, e)
		}
		length := u16(h)
		if length < 1 {
			return nil, fmt.Errorf("hdcopy track %d: empty block", i)
		}
		block, e := read(r, pos+3, length-1)
		if e != nil {
			return nil, e
		}
		decoded, e := decodeTrack(block, h[2], f.unit)
		if e != nil {
			return nil, fmt.Errorf("hdcopy track %d: %w", i, e)
		}
		f.extents[i].data = decoded
		pos += int64(2 + length)
	}
	return f, nil
}
func decodeTrack(b []byte, escape byte, size int) ([]byte, error) {
	out := make([]byte, 0, size)
	for pos := 0; pos < len(b); {
		v, count := b[pos], 1
		pos++
		if v == escape {
			if len(b)-pos < 2 {
				return nil, fmt.Errorf("truncated RLE escape")
			}
			v, count = b[pos], int(b[pos+1])
			pos += 2
			if count == 0 {
				return nil, fmt.Errorf("zero RLE count")
			}
		}
		if count > size-len(out) {
			return nil, fmt.Errorf("RLE track overflow")
		}
		for j := 0; j < count; j++ {
			out = append(out, v)
		}
	}
	if len(out) != size {
		return nil, fmt.Errorf("RLE track underflow")
	}
	return out, nil
}

func (f *File) WriteAt([]byte, int64) (int, error)    { return 0, fmt.Errorf("floppy: read-only") }
func (f *File) String() string                        { return "<" + f.format + ">" }
func (f *File) Type() string                          { return "file" }
func (f *File) Freeze()                               {}
func (f *File) Truth() starlark.Bool                  { return true }
func (f *File) Hash() (uint32, error)                 { return 0, fmt.Errorf("unhashable floppy") }
func (f *File) Attr(n string) (starlark.Value, error) { return starfile.Attr(f, n), nil }
func (f *File) AttrNames() []string                   { return starfile.AttrNames() }

var openers = map[string]func(storage.Reader) (*File, error){"diskdupe": OpenDiskDupe, "hdcopy": OpenHDCopy, "duplicator": OpenDuplicator}

func Builtin(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if e := starlark.UnpackArgs(b.Name(), args, kwargs, "file", &value); e != nil {
		return nil, e
	}
	r, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("%s: want file", b.Name())
	}
	open, ok := openers[b.Name()]
	if !ok {
		return nil, fmt.Errorf("unknown floppy format %s", b.Name())
	}
	return open(r)
}
func init() {
	for name, open := range openers {
		auto.Register(name, 44, func(p []byte, r storage.Reader, _ auto.Options) (auto.View, error) {
			match := false
			switch name {
			case "diskdupe":
				match = bytes.HasPrefix(p, []byte(ddiMagic))
			case "duplicator":
				match = bytes.HasPrefix(p, []byte(duplicatorMagic))
			case "hdcopy":
				match = hdCandidate(p)
			}
			if !match {
				return nil, auto.ErrNoMatch
			}
			f, e := open(r)
			if e != nil {
				return nil, e
			}
			missing, filled := 0, 0
			for _, v := range f.extents {
				if v.missing {
					missing++
				} else if v.offset < 0 && v.data == nil {
					filled++
				}
			}
			attrs := map[string]any{"cylinders": f.cylinders, "heads": f.heads, "sectors_per_track": f.sectors, "sector_size": 512, "logical_bytes": f.Size(), "omitted_units": missing, "filled_units": filled, "unit_bytes": f.unit}
			if name == "duplicator" {
				attrs["checksums_verified"] = false
			}
			return &auto.DecodedView{Reader: f, Name: "disk.img", Format: name, Attributes: attrs}, nil
		})
	}
}
