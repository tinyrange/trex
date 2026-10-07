// Package androidlp reads Android logical-partition (liblp) metadata and
// presents linear/zero extents as portable files. Layout follows AOSP's
// fs_mgr/liblp/include/liblp/metadata_format.h, versions 10.0 through 10.2.
package androidlp

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/tinyrange/trex/storage"
)

type Geometry struct{ MetadataMaxSize, SlotCount, BlockSize uint32 }
type Extent struct {
	Sectors, Sector uint64
	Type, Source    uint32
}
type Group struct {
	Name        string
	Flags       uint32
	MaximumSize uint64
}
type Device struct {
	Name                              string
	FirstSector, Size                 uint64
	Alignment, AlignmentOffset, Flags uint32
}
type Partition struct {
	Name                   string
	Attributes, GroupIndex uint32
	Extents                []Extent
	Data                   storage.Reader
}
type Volume struct {
	Geometry                       Geometry
	Major, Minor                   uint16
	Flags, Slot                    uint32
	BackupGeometry, BackupMetadata bool
	Groups                         []Group
	Devices                        []Device
	Partitions                     []Partition
}

func read(source storage.Reader, off int64, size uint32) ([]byte, error) {
	if off < 0 || int64(size) > source.Size()-off {
		return nil, io.ErrUnexpectedEOF
	}
	b := make([]byte, int(size))
	_, err := io.ReadFull(io.NewSectionReader(source, off, int64(size)), b)
	return b, err
}

var le = binary.LittleEndian

func geometry(source storage.Reader, off int64) (Geometry, error) {
	b, err := read(source, off, 4096)
	if err != nil {
		return Geometry{}, err
	}
	size := le.Uint32(b[4:])
	if le.Uint32(b) != 0x616c4467 || size != 52 {
		return Geometry{}, fmt.Errorf("invalid geometry header")
	}
	want := append([]byte(nil), b[8:40]...)
	clear(b[8:40])
	got := sha256.Sum256(b[:size])
	if !bytes.Equal(want, got[:]) {
		return Geometry{}, fmt.Errorf("geometry checksum mismatch")
	}
	g := Geometry{le.Uint32(b[40:]), le.Uint32(b[44:]), le.Uint32(b[48:])}
	if g.MetadataMaxSize < 512 || g.MetadataMaxSize%512 != 0 || g.MetadataMaxSize > 16<<20 || g.SlotCount == 0 || g.SlotCount > 32 || g.BlockSize < 512 || g.BlockSize%512 != 0 {
		return Geometry{}, fmt.Errorf("invalid or excessive geometry")
	}
	if 12288+int64(g.MetadataMaxSize)*int64(g.SlotCount)*2 > source.Size() {
		return Geometry{}, fmt.Errorf("metadata copies exceed input")
	}
	return g, nil
}

// Open selects a metadata slot, trying its backup if the primary is invalid.
// source is the raw super partition (not an Android sparse wrapper). Device 0
// is bound to source; additional physical devices must be supplied by name.
// Returned files borrow these readers and never extract or allocate payloads.
func Open(source storage.Reader, slot uint32, devices map[string]storage.Reader) (*Volume, error) {
	if source == nil || source.Size() < 12288 {
		return nil, fmt.Errorf("android super: truncated input")
	}
	g, err := geometry(source, 4096)
	backup := false
	if err != nil {
		g, err = geometry(source, 8192)
		backup = true
	}
	if err != nil {
		return nil, fmt.Errorf("android super: no valid geometry: %w", err)
	}
	if slot >= g.SlotCount {
		return nil, fmt.Errorf("android super: slot %d outside %d slots", slot, g.SlotCount)
	}
	off := int64(12288) + int64(g.MetadataMaxSize)*int64(slot)
	v, primaryErr := metadata(source, off, g, slot, devices)
	if primaryErr != nil {
		v, err = metadata(source, off+int64(g.MetadataMaxSize)*int64(g.SlotCount), g, slot, devices)
		if err != nil {
			return nil, fmt.Errorf("android super: primary: %v; backup: %w", primaryErr, err)
		}
		v.BackupMetadata = true
	}
	v.BackupGeometry = backup
	return v, nil
}

func name(b []byte, slot uint32, suffixed bool) (string, error) {
	end := bytes.IndexByte(b, 0)
	if end < 0 {
		end = len(b)
	}
	if end == 0 {
		return "", fmt.Errorf("empty name")
	}
	for _, c := range b[:end] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return "", fmt.Errorf("invalid name")
		}
	}
	for _, c := range b[end:] {
		if c != 0 {
			return "", fmt.Errorf("nonzero name padding")
		}
	}
	n := string(b[:end])
	if suffixed {
		n += "_" + string(rune('a'+slot))
	}
	return n, nil
}

func metadata(source storage.Reader, off int64, g Geometry, slot uint32, readers map[string]storage.Reader) (*Volume, error) {
	h, err := read(source, off, 128)
	if err != nil {
		return nil, err
	}
	major, minor, hs := le.Uint16(h[4:]), le.Uint16(h[6:]), le.Uint32(h[8:])
	if le.Uint32(h) != 0x414c5030 || major != 10 || minor > 2 || (minor < 2 && hs != 128) || (minor == 2 && hs != 256) {
		return nil, fmt.Errorf("unsupported metadata header %d.%d size %d", major, minor, hs)
	}
	ts := le.Uint32(h[44:])
	if hs > g.MetadataMaxSize || ts > g.MetadataMaxSize-hs {
		return nil, fmt.Errorf("tables exceed metadata slot")
	}
	b, err := read(source, off, hs+ts)
	if err != nil {
		return nil, err
	}
	want := append([]byte(nil), b[12:44]...)
	clear(b[12:44])
	got := sha256.Sum256(b[:hs])
	if !bytes.Equal(want, got[:]) {
		return nil, fmt.Errorf("header checksum mismatch")
	}
	got = sha256.Sum256(b[hs:])
	if !bytes.Equal(b[48:80], got[:]) {
		return nil, fmt.Errorf("tables checksum mismatch")
	}
	v := &Volume{Geometry: g, Major: major, Minor: minor, Slot: slot}
	if minor == 2 {
		v.Flags = le.Uint32(b[128:])
	}
	tables := make([][][]byte, 4)
	widths := []uint32{52, 24, 48, 64}
	var occupied [][2]uint64
	for i, width := range widths {
		d := b[80+i*12:]
		start, count, stride := le.Uint32(d), le.Uint32(d[4:]), le.Uint32(d[8:])
		end := uint64(start) + uint64(count)*uint64(stride)
		if stride != width || end > uint64(ts) {
			return nil, fmt.Errorf("invalid table %d bounds or entry size", i)
		}
		if count != 0 {
			for _, r := range occupied {
				if uint64(start) < r[1] && end > r[0] {
					return nil, fmt.Errorf("overlapping tables")
				}
			}
			occupied = append(occupied, [2]uint64{uint64(start), end})
		}
		tables[i] = make([][]byte, count)
		for j := uint32(0); j < count; j++ {
			tables[i][j] = b[hs+start+j*stride : hs+start+(j+1)*stride]
		}
	}
	for _, row := range tables[2] {
		flags := le.Uint32(row[36:])
		n, err := name(row[:36], slot, flags&1 != 0)
		if err != nil || flags & ^uint32(1) != 0 {
			return nil, fmt.Errorf("invalid group")
		}
		v.Groups = append(v.Groups, Group{n, flags, le.Uint64(row[40:])})
	}
	bound := make([]storage.Reader, len(tables[3]))
	for i, row := range tables[3] {
		d := Device{FirstSector: le.Uint64(row), Size: le.Uint64(row[16:]), Alignment: le.Uint32(row[8:]), AlignmentOffset: le.Uint32(row[12:]), Flags: le.Uint32(row[60:])}
		d.Name, err = name(row[24:60], slot, d.Flags&1 != 0)
		if err != nil || d.Flags & ^uint32(1) != 0 || d.Size > math.MaxInt64 || d.Size%512 != 0 || d.FirstSector > d.Size/512 {
			return nil, fmt.Errorf("invalid block device")
		}
		if i == 0 {
			bound[i] = source
		} else {
			bound[i] = readers[d.Name]
		}
		if bound[i] == nil || uint64(bound[i].Size()) < d.Size {
			return nil, fmt.Errorf("missing or truncated physical device %q", d.Name)
		}
		v.Devices = append(v.Devices, d)
	}
	if len(bound) == 0 {
		return nil, fmt.Errorf("no block devices")
	}
	reserve := uint64(12288) + uint64(g.MetadataMaxSize)*uint64(g.SlotCount)*2
	if v.Devices[0].FirstSector < (reserve+511)/512 {
		return nil, fmt.Errorf("logical sectors overlap metadata")
	}
	exts := make([]Extent, len(tables[1]))
	for i, row := range tables[1] {
		e := Extent{Sectors: le.Uint64(row), Type: le.Uint32(row[8:]), Sector: le.Uint64(row[12:]), Source: le.Uint32(row[20:])}
		if e.Sectors == 0 || e.Sectors > math.MaxInt64/512 {
			return nil, fmt.Errorf("invalid extent size")
		}
		switch e.Type {
		case 0:
			if e.Source >= uint32(len(v.Devices)) {
				return nil, fmt.Errorf("invalid extent device")
			}
			d := v.Devices[e.Source]
			if e.Sector < d.FirstSector || e.Sector > d.Size/512 || e.Sectors > d.Size/512-e.Sector {
				return nil, fmt.Errorf("extent exceeds device or overlaps metadata")
			}
		case 1:
			if e.Sector != 0 || e.Source != 0 {
				return nil, fmt.Errorf("invalid zero extent")
			}
		default:
			return nil, fmt.Errorf("unsupported extent type %d", e.Type)
		}
		exts[i] = e
	}
	seen := map[string]bool{}
	groupSizes := make([]uint64, len(v.Groups))
	for _, row := range tables[0] {
		p := Partition{Attributes: le.Uint32(row[36:]), GroupIndex: le.Uint32(row[48:])}
		p.Name, err = name(row[:36], slot, p.Attributes&2 != 0)
		mask := uint32(3)
		if minor >= 1 {
			mask = 15
		}
		first, count := le.Uint32(row[40:]), le.Uint32(row[44:])
		if err != nil || seen[p.Name] || p.Attributes & ^mask != 0 || p.GroupIndex >= uint32(len(v.Groups)) || uint64(first)+uint64(count) > uint64(len(exts)) {
			return nil, fmt.Errorf("invalid partition %q", p.Name)
		}
		seen[p.Name] = true
		p.Extents = append([]Extent(nil), exts[first:first+count]...)
		f := &extentFile{extents: p.Extents, readers: bound}
		for _, e := range p.Extents {
			if int64(e.Sectors)*512 > math.MaxInt64-f.size {
				return nil, fmt.Errorf("partition size overflow")
			}
			f.size += int64(e.Sectors) * 512
		}
		groupSizes[p.GroupIndex] += uint64(f.size)
		if groupSizes[p.GroupIndex] > math.MaxInt64 {
			return nil, fmt.Errorf("group size overflow")
		}
		p.Data = f
		v.Partitions = append(v.Partitions, p)
	}
	for i, group := range v.Groups {
		if group.MaximumSize != 0 && groupSizes[i] > group.MaximumSize {
			return nil, fmt.Errorf("group %q exceeds maximum", group.Name)
		}
	}
	return v, nil
}

type extentFile struct {
	extents []Extent
	readers []storage.Reader
	size    int64
}

func (f *extentFile) Size() int64 { return f.size }
func (f *extentFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.size {
		return 0, io.EOF
	}
	requested := len(p)
	if int64(len(p)) > f.size-off {
		p = p[:f.size-off]
	}
	n := 0
	for _, e := range f.extents {
		length := int64(e.Sectors) * 512
		if off >= length {
			off -= length
			continue
		}
		chunk := p[:min(int64(len(p)), length-off)]
		if e.Type == 1 {
			clear(chunk)
		} else {
			got, err := f.readers[e.Source].ReadAt(chunk, int64(e.Sector)*512+off)
			if got != len(chunk) || err != nil && err != io.EOF {
				return n + got, errOrShort(err)
			}
		}
		n += len(chunk)
		p = p[len(chunk):]
		off = 0
		if len(p) == 0 {
			break
		}
	}
	if n < requested {
		return n, io.EOF
	}
	return n, nil
}
func errOrShort(err error) error {
	if err == nil || err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
