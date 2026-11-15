package ckd

import (
	"bytes"
	"fmt"
	"sort"
)

// Edit changes a volume without moving anything, for writing it out with
// Compress. Removed data sets' format-1 DSCBs and the format-3 DSCBs their
// chains name become format-0 (all zero) DSCBs, which the format-4 DSCB
// counts as free. The format-4 DSCB also stops naming the VTOC index
// (DS4IVTOC) and marks the format-5 free-space DSCBs not valid (DS4DOSBT),
// so the operating system recomputes free space from the remaining extents
// the next time it allocates on the volume; a remaining VTOC index data set
// is kept as ordinary data. Blanked data sets keep their records with zero
// data. Members added to a partitioned data set are written on its free
// tracks after DS1LSTAR, with a rebuilt directory. Every track outside the
// remaining data sets, the VTOC and track 0 (volume label and IPL records)
// is a null track. Catalog entries are not changed.
type Edit struct {
	Disk     *Disk
	Removed  []string
	vol      *Volume
	tracks   uint32
	override map[uint32][]Record
	vtoc     map[uint32][]Record
	f1       map[string]loc // format-1 DSCB of each data set
	at       map[uint64]loc // every DSCB by track*256+record
	f4       loc
	removed  map[string]bool
	blank    map[string]bool
	// live records of compacted data sets: track -> record number bitmap
	live      map[uint32]*[4]uint64
	compacted map[string]bool
	kept      map[string]map[string][]byte // KeepMembers' remaining entries
}

// Trimmed is an Edit that only removes data sets.
type Trimmed = Edit

type loc struct {
	track uint32
	index int
}

const (
	ds4DOSBT = 0x80 // format-5 DSCBs are not valid
	ds4IVTOC = 0x08 // the VTOC is indexed
)

// Trim removes the named data sets from the volume.
func Trim(d *Disk, remove []string) (*Edit, error) {
	e, err := NewEdit(d)
	if err != nil {
		return nil, err
	}
	if err := e.Remove(remove); err != nil {
		return nil, err
	}
	return e, nil
}

// NewEdit reads the volume's VTOC for editing.
func NewEdit(d *Disk) (*Edit, error) {
	v, err := d.ReadVTOC(1000000)
	if err != nil {
		return nil, err
	}
	e := &Edit{Disk: d, vol: v, tracks: uint32((d.Source.Size() - 512) / int64(d.TrackSize)),
		override: map[uint32][]Record{}, vtoc: map[uint32][]Record{}, f1: map[string]loc{}, at: map[uint64]loc{},
		removed: map[string]bool{}, blank: map[string]bool{}, live: map[uint32]*[4]uint64{}, compacted: map[string]bool{}, kept: map[string]map[string][]byte{}}
	found4 := false
	for tr := v.VTOC.First; tr <= v.VTOC.Last; tr++ {
		rs, err := d.Track(tr)
		if err != nil {
			return nil, err
		}
		e.vtoc[tr] = rs
		for i, r := range rs {
			if r.Number == 0 || len(r.Key) != 44 || len(r.Data) != 96 {
				continue
			}
			l := loc{tr, i}
			e.at[uint64(tr)*256+uint64(r.Number)] = l
			switch r.Data[0] {
			case 0xf1:
				e.f1[Identifier(r.Key)] = l
			case 0xf4:
				if !found4 {
					e.f4, found4 = l, true
				}
			}
		}
	}
	if !found4 {
		return nil, fmt.Errorf("ckd edit: no format-4 DSCB")
	}
	return e, nil
}

func (e *Edit) dataset(name string) (*Dataset, error) {
	for _, ds := range e.vol.Datasets {
		if ds.Name == name {
			if e.removed[name] {
				return nil, fmt.Errorf("ckd edit: %s is removed", name)
			}
			return ds, nil
		}
	}
	return nil, fmt.Errorf("ckd edit: %s is not on volume %s", name, e.vol.Serial)
}

// vtocRecord returns a writable copy of a VTOC record.
func (e *Edit) vtocRecord(l loc) *Record {
	return &e.writableTrack(l.track, e.vtoc[l.track])[l.index]
}

func (e *Edit) writableTrack(tr uint32, rs []Record) []Record {
	if r, ok := e.override[tr]; ok {
		return r
	}
	cp := make([]Record, len(rs))
	for i, r := range rs {
		cp[i] = Record{Cylinder: r.Cylinder, Head: r.Head, Number: r.Number, Key: bytes.Clone(r.Key), Data: bytes.Clone(r.Data)}
	}
	e.override[tr] = cp
	return cp
}

// Remove removes data sets; names not on the volume are an error.
func (e *Edit) Remove(names []string) error {
	freed := 0
	for _, name := range names {
		if _, err := e.dataset(name); err != nil {
			return err
		}
		l := e.f1[name]
		chain := []loc{l}
		ptr := bytes.Clone(e.vtoc[l.track][l.index].Data[91:96])
		for len(chain) < 256 && !bytes.Equal(ptr, make([]byte, 5)) {
			tr, err := e.Disk.address(ptr)
			if err != nil {
				return err
			}
			next, ok := e.at[uint64(tr)*256+uint64(ptr[4])]
			if !ok || e.vtoc[next.track][next.index].Data[0] != 0xf3 {
				return fmt.Errorf("ckd edit: %s names a missing format-3 DSCB", name)
			}
			chain = append(chain, next)
			ptr = bytes.Clone(e.vtoc[next.track][next.index].Data[91:96])
		}
		for _, c := range chain {
			r := e.vtocRecord(c)
			clear(r.Key)
			clear(r.Data)
			freed++
		}
		e.removed[name] = true
		e.Removed = append(e.Removed, name)
	}
	f4 := e.vtocRecord(e.f4)
	free := int(be.Uint16(f4.Data[6:8])) + freed
	if free > 0xffff {
		return fmt.Errorf("ckd edit: format-0 DSCB count overflows")
	}
	be.PutUint16(f4.Data[6:8], uint16(free))
	f4.Data[14] = f4.Data[14]&^ds4IVTOC | ds4DOSBT
	return nil
}

// Blank keeps a data set's records (counts and keys) with zero data, for
// data sets whose content the system does not read before rewriting it.
func (e *Edit) Blank(names []string) error {
	for _, name := range names {
		if _, err := e.dataset(name); err != nil {
			return err
		}
		e.blank[name] = true
	}
	return nil
}

// Compact zeroes the data of a traditional PDS's records that neither the
// directory nor any member uses: space left by members that were replaced
// or deleted without compressing the library. A member uses the records
// from its directory TTR to its end-of-file record. Records keep their
// counts, so the library's layout is unchanged. Compact before AddMembers.
func (e *Edit) Compact(names []string) (dead int, err error) {
	for _, name := range names {
		ds, err := e.dataset(name)
		if err != nil {
			return dead, err
		}
		if !ds.IsPDS() {
			return dead, fmt.Errorf("ckd edit: %s is not a traditional PDS", name)
		}
		members, err := ds.Members(1000000)
		if err != nil {
			return dead, err
		}
		if kept, ok := e.kept[name]; ok {
			var remaining []Member
			for _, m := range members {
				if _, ok := kept[m.Name]; ok {
					remaining = append(remaining, m)
				}
			}
			members = remaining
		}
		mark := func(abs uint32, n byte) {
			m := e.live[abs]
			if m == nil {
				m = new([4]uint64)
				e.live[abs] = m
			}
			m[n>>6] |= 1 << (n & 63)
		}
		abs := func(rel uint32) (uint32, bool) {
			for _, x := range ds.Extents {
				if rel <= x.Last-x.First {
					return x.First + rel, true
				}
				rel -= x.Last - x.First + 1
			}
			return 0, false
		}
		// The directory: keyed 256-byte blocks from the start, and an
		// end-of-file record after them if there is one.
		dirEnd := false
		for t := uint32(0); !dirEnd; t++ {
			a, ok := abs(t)
			if !ok {
				return dead, fmt.Errorf("ckd edit: %s: directory without end", name)
			}
			rs, err := e.Disk.Track(a)
			if err != nil {
				return dead, err
			}
			for _, r := range rs {
				if r.Number == 0 {
					continue
				}
				if len(r.Key) != 8 || len(r.Data) != 256 {
					if len(r.Data) == 0 {
						mark(a, r.Number) // the directory's end-of-file record
					}
					dirEnd = true
					break
				}
				mark(a, r.Number)
			}
		}
		for _, m := range members {
			done := false
			for t := m.Track; !done; t++ {
				a, ok := abs(t)
				if !ok {
					return dead, fmt.Errorf("ckd edit: %s(%s) runs past the data set", name, m.Name)
				}
				rs, err := e.Disk.Track(a)
				if err != nil {
					return dead, err
				}
				for _, r := range rs {
					if r.Number == 0 || (t == m.Track && r.Number < m.Record) {
						continue
					}
					mark(a, r.Number)
					if len(r.Data) == 0 {
						done = true
						break
					}
				}
			}
		}
		for t := uint32(0); t < ds.Tracks(); t++ {
			a, _ := abs(t)
			rs, err := e.Disk.Track(a)
			if err != nil {
				return dead, err
			}
			for _, r := range rs {
				if r.Number != 0 && !e.isLive(a, r.Number) {
					dead += len(r.Data)
				}
			}
		}
		e.compacted[name] = true
	}
	return dead, nil
}

func (e *Edit) isLive(tr uint32, n byte) bool {
	m := e.live[tr]
	return m != nil && m[n>>6]&(1<<(n&63)) != 0
}

// NewMember is a partitioned data set member to add: fixed-length records.
type NewMember struct {
	Name    string
	Records [][]byte
}

// AddMembers writes members into a traditional PDS with fixed-length
// records: their blocks go on the free tracks after DS1LSTAR, two blocks of
// at most the data set's block size per track (well within any CKD track),
// each member ending with an end-of-file record; the directory is rebuilt
// with the new entries replacing members of the same names, and DS1LSTAR
// names the last record written (DS1TRBAL zero: the track is full).
func (e *Edit) AddMembers(name string, members []NewMember) error {
	ds, err := e.dataset(name)
	if err != nil {
		return err
	}
	if !ds.IsPDS() || ds.RecordFormat&0xc0 != 0x80 || ds.RecordLength == 0 || ds.BlockSize < ds.RecordLength {
		return fmt.Errorf("ckd edit: %s is not a fixed-record PDS", name)
	}
	lrecl, blk := int(ds.RecordLength), int(ds.BlockSize)/int(ds.RecordLength)*int(ds.RecordLength)
	existing, err := ds.Members(100000)
	if err != nil {
		return err
	}
	entries := map[string][]byte{} // name -> directory entry after the name
	for _, m := range existing {
		entries[m.Name] = append([]byte{byte(m.Track >> 8), byte(m.Track), m.Record, m.Info}, m.UserData...)
	}
	rel := func(t uint32) (uint32, error) { // relative track -> absolute
		n := t
		for _, x := range ds.Extents {
			if n <= x.Last-x.First {
				return x.First + n, nil
			}
			n -= x.Last - x.First + 1
		}
		return 0, fmt.Errorf("ckd edit: %s has no relative track %d", name, t)
	}
	f1 := e.vtoc[e.f1[name].track][e.f1[name].index]
	track := uint32(be.Uint16(f1.Data[54:56])) + 1 // DS1LSTAR TT: start on the next track
	var lastTrack uint32
	var lastRecord byte
	for _, m := range members {
		if len(m.Name) == 0 || len(m.Name) > 8 {
			return fmt.Errorf("ckd edit: invalid member name %q", m.Name)
		}
		var blocks [][]byte
		var cur []byte
		for _, r := range m.Records {
			if len(r) != lrecl {
				return fmt.Errorf("ckd edit: %s(%s): record of %d bytes, not %d", name, m.Name, len(r), lrecl)
			}
			if len(cur)+lrecl > blk {
				blocks = append(blocks, cur)
				cur = nil
			}
			cur = append(cur, r...)
		}
		if cur != nil {
			blocks = append(blocks, cur)
		}
		blocks = append(blocks, nil) // end of file
		var first [3]byte
		for i := 0; i < len(blocks); {
			abs, err := rel(track)
			if err != nil {
				return err
			}
			base, err := e.Disk.Track(abs)
			if err != nil {
				return err
			}
			cyl, head := uint16(abs/e.Disk.Heads), uint16(abs%e.Disk.Heads)
			recs := []Record{{Cylinder: cyl, Head: head, Number: 0, Data: make([]byte, 8)}}
			if len(base) > 0 && base[0].Number == 0 {
				recs[0].Data = bytes.Clone(base[0].Data)
			}
			for n := 0; n < 2 && i < len(blocks); n++ {
				rec := byte(len(recs))
				if i == 0 {
					be.PutUint16(first[:], uint16(track))
					first[2] = rec
				}
				recs = append(recs, Record{Cylinder: cyl, Head: head, Number: rec, Data: blocks[i]})
				lastTrack, lastRecord = track, rec
				i++
				// The end-of-file record also fits after two blocks.
				if n == 1 && i == len(blocks)-1 {
					recs = append(recs, Record{Cylinder: cyl, Head: head, Number: byte(len(recs))})
					lastRecord = byte(len(recs) - 1)
					i++
				}
			}
			e.override[abs] = recs
			track++
		}
		entries[m.Name] = append(first[:], 0)
	}
	if err := e.writeDirectory(ds, entries); err != nil {
		return err
	}
	if len(members) > 0 {
		f := e.vtocRecord(e.f1[name])
		be.PutUint16(f.Data[54:56], uint16(lastTrack))
		f.Data[56] = lastRecord
		be.PutUint16(f.Data[57:59], 0)
	}
	return nil
}

// writeDirectory rewrites a PDS directory in place with the entries (name ->
// the entry after the name), in name order, ending with the end marker.
// The directory is the 256-byte keyed blocks from the start of the data set
// up to the first record that is not one; unused blocks are zeroed.
func (e *Edit) writeDirectory(ds *Dataset, entries map[string][]byte) error {
	name := ds.Name
	rel := func(t uint32) (uint32, error) {
		n := t
		for _, x := range ds.Extents {
			if n <= x.Last-x.First {
				return x.First + n, nil
			}
			n -= x.Last - x.First + 1
		}
		return 0, fmt.Errorf("ckd edit: %s has no relative track %d", name, t)
	}
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	var dir [][]byte // directory entries with their names
	for _, n := range names {
		nm := bytes.Repeat([]byte{0x40}, 8)
		copy(nm, encodeEBCDIC(n))
		dir = append(dir, append(nm, entries[n]...))
	}
	sort.Slice(dir, func(i, j int) bool { return bytes.Compare(dir[i][:8], dir[j][:8]) < 0 })
	dir = append(dir, append(bytes.Repeat([]byte{0xff}, 8), 0, 0, 0, 0))
	pos := 0
	for t := uint32(0); pos >= 0; t++ {
		abs, err := rel(t)
		if err != nil {
			return err
		}
		base, err := e.Disk.Track(abs)
		if err != nil {
			return err
		}
		if len(base) < 2 || len(base[1].Key) != 8 || len(base[1].Data) != 256 {
			// The directory ended with the previous track.
			if pos < len(dir) {
				return fmt.Errorf("ckd edit: %s: directory full", name)
			}
			break
		}
		rs := e.writableTrack(abs, base)
		for i := range rs {
			r := &rs[i]
			if r.Number == 0 {
				continue
			}
			if len(r.Key) != 8 || len(r.Data) != 256 {
				if pos < len(dir) {
					return fmt.Errorf("ckd edit: %s: directory full", name)
				}
				pos = -1
				break
			}
			clear(r.Key)
			clear(r.Data)
			if pos >= len(dir) {
				continue
			}
			used := 2
			for pos < len(dir) && used+len(dir[pos]) <= 256 {
				copy(r.Data[used:], dir[pos])
				copy(r.Key, dir[pos][:8])
				used += len(dir[pos])
				pos++
			}
			be.PutUint16(r.Data, uint16(used))
		}
		if t > 1000 {
			return fmt.Errorf("ckd edit: %s: directory without end", name)
		}
	}
	return nil
}

// KeepMembers removes every member of a traditional PDS but the named ones
// (and aliases of them, which share their TTR) from its directory; a later
// Compact of the data set zeroes the removed members' records.
func (e *Edit) KeepMembers(name string, keep []string) error {
	ds, err := e.dataset(name)
	if err != nil {
		return err
	}
	if !ds.IsPDS() {
		return fmt.Errorf("ckd edit: %s is not a traditional PDS", name)
	}
	members, err := ds.Members(1000000)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, n := range keep {
		want[n] = true
	}
	starts := map[[2]uint32]bool{}
	for _, m := range members {
		if want[m.Name] {
			starts[[2]uint32{m.Track, uint32(m.Record)}] = true
		}
	}
	entries := map[string][]byte{}
	for _, m := range members {
		if want[m.Name] || (m.Alias && starts[[2]uint32{m.Track, uint32(m.Record)}]) {
			entries[m.Name] = append([]byte{byte(m.Track >> 8), byte(m.Track), m.Record, m.Info}, m.UserData...)
		}
	}
	if err := e.writeDirectory(ds, entries); err != nil {
		return err
	}
	e.kept[name] = entries
	return nil
}

// Holds reports whether a track keeps content (otherwise it is null).
func (e *Edit) Holds(tr uint32) bool {
	if tr >= e.tracks {
		return false
	}
	if tr == 0 || (tr >= e.vol.VTOC.First && tr <= e.vol.VTOC.Last) {
		return true
	}
	_, ok := e.owner(tr)
	return ok
}

// owner is the remaining data set holding a track.
func (e *Edit) owner(tr uint32) (*Dataset, bool) {
	for _, ds := range e.vol.Datasets {
		if e.removed[ds.Name] {
			continue
		}
		for _, x := range ds.Extents {
			if tr >= x.First && tr <= x.Last {
				return ds, true
			}
		}
	}
	return nil, false
}

// Kept counts the tracks that hold content.
func (e *Edit) Kept() uint32 {
	n := uint32(0)
	for tr := uint32(0); tr < e.tracks; tr++ {
		if e.Holds(tr) {
			n++
		}
	}
	return n
}

// Track returns a held track's records with the edits applied.
func (e *Edit) Track(tr uint32) ([]Record, error) {
	if r, ok := e.override[tr]; ok {
		return r, nil
	}
	rs, err := e.Disk.Track(tr)
	if err != nil {
		return nil, err
	}
	if ds, ok := e.owner(tr); ok && (e.blank[ds.Name] || e.compacted[ds.Name]) {
		out := make([]Record, len(rs))
		for i, r := range rs {
			out[i] = r
			if r.Number != 0 && (e.blank[ds.Name] || !e.isLive(tr, r.Number)) {
				out[i] = Record{Cylinder: r.Cylinder, Head: r.Head, Number: r.Number, Key: make([]byte, len(r.Key)), Data: make([]byte, len(r.Data))}
				if e.blank[ds.Name] {
					out[i].Key = r.Key
				}
			}
		}
		return out, nil
	}
	return rs, nil
}

// Tracks is the volume's track count.
func (e *Edit) Tracks() uint32 { return e.tracks }

// encodeEBCDIC encodes member names as Identifier decodes them: letters,
// digits, @ # $ and %XX escapes for other bytes.
func encodeEBCDIC(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) {
			var b byte
			if _, err := fmt.Sscanf(s[i+1:i+3], "%02X", &b); err == nil {
				out = append(out, b)
				i += 2
				continue
			}
		}
		out = append(out, ebcdicChar(c))
	}
	return out
}

func ebcdicChar(c byte) byte {
	switch {
	case c >= 'A' && c <= 'I':
		return c - 'A' + 0xc1
	case c >= 'J' && c <= 'R':
		return c - 'J' + 0xd1
	case c >= 'S' && c <= 'Z':
		return c - 'S' + 0xe2
	case c >= 'a' && c <= 'i':
		return c - 'a' + 0x81
	case c >= 'j' && c <= 'r':
		return c - 'j' + 0x91
	case c >= 's' && c <= 'z':
		return c - 's' + 0xa2
	case c >= '0' && c <= '9':
		return c - '0' + 0xf0
	case c == '@':
		return 0x7c
	case c == '#':
		return 0x7b
	case c == '$':
		return 0x5b
	case c == '.':
		return 0x4b
	case c == '-':
		return 0x60
	case c == '_':
		return 0x6d
	}
	return 0x40
}
