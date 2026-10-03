package ckd

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// Identifier decodes the invariant EBCDIC dataset/member-name alphabet. Unknown
// bytes are escaped rather than replaced, preserving distinct on-disk names.
func Identifier(b []byte) string {
	var s strings.Builder
	for _, c := range bytes.TrimRight(b, "\x40") {
		switch {
		case c >= 0xc1 && c <= 0xc9:
			s.WriteByte('A' + c - 0xc1)
		case c >= 0xd1 && c <= 0xd9:
			s.WriteByte('J' + c - 0xd1)
		case c >= 0xe2 && c <= 0xe9:
			s.WriteByte('S' + c - 0xe2)
		case c >= 0x81 && c <= 0x89:
			s.WriteByte('a' + c - 0x81)
		case c >= 0x91 && c <= 0x99:
			s.WriteByte('j' + c - 0x91)
		case c >= 0xa2 && c <= 0xa9:
			s.WriteByte('s' + c - 0xa2)
		case c >= 0xf0 && c <= 0xf9:
			s.WriteByte('0' + c - 0xf0)
		case c == 0x4b:
			s.WriteByte('.')
		case c == 0x5b:
			s.WriteByte('$')
		case c == 0x7b:
			s.WriteByte('#')
		case c == 0x7c:
			s.WriteByte('@')
		case c == 0x60:
			s.WriteByte('-')
		case c == 0x6d:
			s.WriteByte('_')
		case c == 0x40:
			s.WriteByte(' ')
		default:
			fmt.Fprintf(&s, "%%%02X", c)
		}
	}
	return s.String()
}

type Extent struct {
	First, Last uint32
	Sequence    byte
}
type Dataset struct {
	Disk                    *Disk
	Name, Volume            string
	VolumeSequence          uint16
	Organization            uint16
	RecordFormat            byte
	BlockSize, RecordLength uint16
	SMSFlags, Flags         byte
	Extents                 []Extent
	DSCB                    []byte
}
type Volume struct {
	Disk     *Disk
	Serial   string
	VTOC     Extent
	Datasets []*Dataset
	DSCBs    [][]byte
}

func (d *Disk) address(p []byte) (uint32, error) {
	head := uint32(be.Uint16(p[2:4]))
	if head >= d.Heads {
		return 0, fmt.Errorf("ckd: invalid CCHH %x", p[:4])
	}
	return uint32(be.Uint16(p[:2]))*d.Heads + head, nil
}
func (d *Disk) extent(p []byte) (Extent, error) {
	a, e := d.address(p[2:6])
	if e != nil {
		return Extent{}, e
	}
	b, e := d.address(p[6:10])
	if e != nil {
		return Extent{}, e
	}
	if p[0] == 0 || b < a {
		return Extent{}, fmt.Errorf("ckd: invalid extent %x", p)
	}
	return Extent{a, b, p[1]}, nil
}
func (d *Disk) recordAt(p []byte) (Record, error) {
	t, e := d.address(p)
	if e != nil {
		return Record{}, e
	}
	rs, e := d.Track(t)
	if e != nil {
		return Record{}, e
	}
	for _, r := range rs {
		if r.Number == p[4] {
			return r, nil
		}
	}
	return Record{}, fmt.Errorf("ckd: missing CCHHR %x", p)
}
func dscb(r Record) ([]byte, error) {
	if len(r.Key) != 44 || len(r.Data) != 96 {
		return nil, fmt.Errorf("ckd: invalid DSCB lengths %d/%d", len(r.Key), len(r.Data))
	}
	b := make([]byte, 140)
	copy(b, r.Key)
	copy(b[44:], r.Data)
	return b, nil
}

// ReadVTOC reads the VOL1-selected VTOC, preserving every DSCB and following
// format-3 extent chains. maxDSCBs bounds hostile or unexpectedly large VTOCs.
func (d *Disk) ReadVTOC(maxDSCBs int) (*Volume, error) {
	if maxDSCBs <= 0 {
		return nil, fmt.Errorf("ckd: maxDSCBs must be positive")
	}
	rs, e := d.Track(0)
	if e != nil {
		return nil, e
	}
	var label []byte
	for _, r := range rs {
		if len(r.Data) >= 80 && bytes.Equal(r.Data[:4], []byte{0xe5, 0xd6, 0xd3, 0xf1}) {
			label = r.Data
			break
		}
	}
	if label == nil {
		return nil, fmt.Errorf("ckd: VOL1 label not found")
	}
	r, e := d.recordAt(label[11:16])
	if e != nil {
		return nil, e
	}
	f4, e := dscb(r)
	if e != nil {
		return nil, e
	}
	if f4[44] != 0xf4 || f4[59] != 1 {
		return nil, fmt.Errorf("ckd: expected single-extent format-4 VTOC")
	}
	ext, e := d.extent(f4[105:115])
	if e != nil {
		return nil, e
	}
	vt, e := d.address(label[11:15])
	if e != nil {
		return nil, e
	}
	if vt < ext.First || vt > ext.Last {
		return nil, fmt.Errorf("ckd: VTOC pointer outside VTOC extent")
	}
	if uint64(ext.Last-ext.First+1) > uint64(maxDSCBs) {
		return nil, fmt.Errorf("ckd: VTOC track limit exceeded")
	}
	v := &Volume{Disk: d, Serial: Identifier(label[4:10]), VTOC: ext}
	index := map[uint64][]byte{}
	for t := ext.First; t <= ext.Last; t++ {
		rs, e := d.Track(t)
		if e != nil {
			return nil, e
		}
		for _, r := range rs {
			if r.Number == 0 {
				continue
			}
			b, e := dscb(r)
			if e != nil {
				return nil, e
			}
			if len(v.DSCBs) >= maxDSCBs {
				return nil, fmt.Errorf("ckd: DSCB limit exceeded")
			}
			key := uint64(t)*256 + uint64(r.Number)
			if _, exists := index[key]; exists {
				return nil, fmt.Errorf("ckd: duplicate DSCB address")
			}
			v.DSCBs = append(v.DSCBs, b)
			index[key] = b
		}
	}
	names := map[string]bool{}
	for _, b := range v.DSCBs {
		if b[44] == 0xf8 {
			return nil, fmt.Errorf("ckd: extended-address format-8 DSCB not supported")
		}
		if b[44] != 0xf1 {
			continue
		}
		ds := &Dataset{Disk: d, Name: Identifier(b[:44]), Volume: Identifier(b[45:51]), VolumeSequence: be.Uint16(b[51:53]), Organization: be.Uint16(b[82:84]), RecordFormat: b[84], BlockSize: be.Uint16(b[86:88]), RecordLength: be.Uint16(b[88:90]), SMSFlags: b[78], Flags: b[61], DSCB: b}
		if ds.Name == "" || ds.Name == "." || ds.Name == ".." || names[ds.Name] {
			return nil, fmt.Errorf("ckd: empty or duplicate dataset name %q", ds.Name)
		}
		names[ds.Name] = true
		add := func(p []byte) error {
			for len(p) >= 10 {
				if p[0] != 0 {
					x, e := d.extent(p[:10])
					if e != nil {
						return e
					}
					ds.Extents = append(ds.Extents, x)
				}
				p = p[10:]
			}
			return nil
		}
		if e := add(b[105:135]); e != nil {
			return nil, e
		}
		ptr := b[135:140]
		seen := map[uint64]bool{}
		for !bytes.Equal(ptr, make([]byte, 5)) {
			t, e := d.address(ptr)
			if e != nil {
				return nil, e
			}
			k := uint64(t)*256 + uint64(ptr[4])
			if seen[k] {
				return nil, fmt.Errorf("ckd: cyclic extent chain for %s", ds.Name)
			}
			seen[k] = true
			next, ok := index[k]
			if !ok || next[44] != 0xf3 {
				return nil, fmt.Errorf("ckd: missing or unsupported extent DSCB for %s", ds.Name)
			}
			if e := add(next[4:44]); e != nil {
				return nil, e
			}
			if e := add(next[45:135]); e != nil {
				return nil, e
			}
			ptr = next[135:140]
			if len(ds.Extents) > 255 {
				return nil, fmt.Errorf("ckd: extent limit exceeded")
			}
		}
		if len(ds.Extents) != int(b[59]) {
			return nil, fmt.Errorf("ckd: %s extent count %d != %d", ds.Name, len(ds.Extents), b[59])
		}
		sort.Slice(ds.Extents, func(i, j int) bool { return ds.Extents[i].Sequence < ds.Extents[j].Sequence })
		for i, x := range ds.Extents {
			if int(x.Sequence) != i {
				return nil, fmt.Errorf("ckd: noncontiguous extent sequence for %s", ds.Name)
			}
			for _, y := range ds.Extents[:i] {
				if x.First <= y.Last && y.First <= x.Last {
					return nil, fmt.Errorf("ckd: overlapping extents for %s", ds.Name)
				}
			}
		}
		v.Datasets = append(v.Datasets, ds)
	}
	return v, nil
}
func (ds *Dataset) Tracks() uint32 {
	var n uint32
	for _, e := range ds.Extents {
		n += e.Last - e.First + 1
	}
	return n
}
func (ds *Dataset) Track(relative uint32) ([]Record, error) {
	for _, e := range ds.Extents {
		n := e.Last - e.First + 1
		if relative < n {
			return ds.Disk.Track(e.First + relative)
		}
		relative -= n
	}
	return nil, fmt.Errorf("ckd: relative track outside dataset %s", ds.Name)
}
func (ds *Dataset) IsPDS() bool { return ds.Organization&0x0200 != 0 && ds.SMSFlags&0x0a == 0 }
