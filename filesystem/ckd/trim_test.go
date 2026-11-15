package ckd

import (
	"bytes"
	"testing"
)

// trimFixture is fixture() with a second data set, KEEP.SEQ on tracks 6-7,
// and an indexed VTOC whose format-4 DSCB counts 5 free DSCBs.
func trimFixture() []byte {
	b := fixture()
	d, err := Open(raw(b))
	if err != nil {
		panic(err)
	}
	var tracks [][]Record
	for t := uint32(0); t < 6; t++ {
		rs, err := d.Track(t)
		if err != nil {
			panic(err)
		}
		tracks = append(tracks, rs)
	}
	f4 := tracks[1][1]
	f4.Data = bytes.Clone(f4.Data)
	be.PutUint16(f4.Data[6:], 5)
	f4.Data[14] = 0x89
	tracks[1][1] = f4
	keep := make([]byte, 140)
	copy(keep, eb("KEEP.SEQ", 44))
	keep[44] = 0xf1
	copy(keep[45:], eb("TEST01", 6))
	keep[52] = 1
	keep[59] = 1
	keep[82] = 0x40
	extent(keep[105:], 0, 6, 7)
	tracks[1] = append(tracks[1], r(4, keep[:44], keep[44:]))
	tracks = append(tracks,
		[]Record{r(0, nil, make([]byte, 8)), r(1, nil, []byte("kept one"))},
		[]Record{r(0, nil, make([]byte, 8)), r(1, nil, []byte("kept two"))})
	return image(tracks)
}

// Trimming removes a data set's DSCBs (following its format-3 chain), counts
// them free, turns the VTOC index off and null-fills its tracks; the
// compressed image reads back with the remaining data set intact.
func TestTrimAndCompress(t *testing.T) {
	d := openTest(t, trimFixture())
	tr, err := Trim(d, []string{"TEST.PDS"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Removed) != 1 || tr.Kept() != 4 {
		t.Fatalf("removed %v, kept %d tracks", tr.Removed, tr.Kept())
	}
	for track, want := range []bool{true, true, false, false, false, false, true, true} {
		if tr.Holds(uint32(track)) != want {
			t.Fatalf("track %d held %v", track, !want)
		}
	}
	header := make([]byte, 512)
	if _, err := d.Source.ReadAt(header, 0); err != nil {
		t.Fatal(err)
	}
	img, err := Compress(tr, header, d.Heads, d.TrackSize)
	if err != nil {
		t.Fatal(err)
	}
	if img.Held != 4 {
		t.Fatalf("held %d tracks", img.Held)
	}
	c, err := OpenCompressed(img)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	v, err := out.ReadVTOC(20)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Datasets) != 1 || v.Datasets[0].Name != "KEEP.SEQ" {
		t.Fatalf("data sets after trim: %+v", v.Datasets)
	}
	vt, _ := out.Track(1)
	for _, n := range []int{2, 3} { // the format-1 and format-3 DSCBs
		if !bytes.Equal(vt[n].Key, make([]byte, 44)) || !bytes.Equal(vt[n].Data, make([]byte, 96)) {
			t.Fatalf("DSCB %d not cleared", vt[n].Number)
		}
	}
	if f4 := vt[1].Data; be.Uint16(f4[6:]) != 7 || f4[14] != 0x81 {
		t.Fatalf("format-4: %d free DSCBs, DS4VTOCI %02X", be.Uint16(f4[6:]), f4[14])
	}
	for track, want := range map[uint32]string{6: "kept one", 7: "kept two"} {
		rs, err := out.Track(track)
		if err != nil || len(rs) != 2 || string(rs[1].Data) != want {
			t.Fatalf("track %d: %v %v", track, rs, err)
		}
	}
	if rs, err := out.Track(3); err != nil || len(rs) != 2 || rs[1].Number != 1 || len(rs[1].Data) != 0 {
		t.Fatalf("null track 3: %v %v", rs, err)
	}
	// The original is unchanged.
	if v0, _ := d.ReadVTOC(20); len(v0.Datasets) != 2 {
		t.Fatal("trim changed its source")
	}
	if _, err := Trim(d, []string{"NOT.THERE"}); err == nil {
		t.Fatal("trimmed a data set the volume does not have")
	}
}

// pdsFixture is trimFixture() with NEW.PDS (FB 80, blocks of 160) on tracks
// 8-11: two keyed directory blocks on its first track, the first holding
// only the end marker, and DS1LSTAR at the second.
func pdsFixture() []byte {
	d, err := Open(raw(trimFixture()))
	if err != nil {
		panic(err)
	}
	var tracks [][]Record
	for t := uint32(0); t < 8; t++ {
		rs, _ := d.Track(t)
		tracks = append(tracks, rs)
	}
	f1 := make([]byte, 140)
	copy(f1, eb("NEW.PDS", 44))
	f1[44] = 0xf1
	copy(f1[45:], eb("TEST01", 6))
	f1[52] = 1
	f1[59] = 1
	f1[82] = 2
	f1[84] = 0x90
	be.PutUint16(f1[86:], 160)
	be.PutUint16(f1[88:], 80)
	f1[100] = 2 // DS1LSTAR: relative track 0, record 2
	extent(f1[105:], 0, 8, 11)
	tracks[1] = append(tracks[1], r(5, f1[:44], f1[44:]))
	end := make([]byte, 256)
	be.PutUint16(end, 14)
	copy(end[2:], bytes.Repeat([]byte{0xff}, 8))
	tracks = append(tracks,
		[]Record{r(0, nil, make([]byte, 8)), r(1, bytes.Repeat([]byte{0xff}, 8), end), r(2, make([]byte, 8), make([]byte, 256))},
		[]Record{r(0, nil, make([]byte, 8))}, []Record{r(0, nil, make([]byte, 8))}, []Record{r(0, nil, make([]byte, 8))})
	return image(tracks)
}

func line(s string) []byte { return append(encodeEBCDIC(s), bytes.Repeat([]byte{0x40}, 80-len(s))...) }

// Members added to a PDS land after DS1LSTAR with a rebuilt directory and
// read back through the PDS reader; a blanked data set keeps its records
// with zero data.
func TestAddMembersAndBlank(t *testing.T) {
	d := openTest(t, pdsFixture())
	e, err := NewEdit(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.AddMembers("NEW.PDS", []NewMember{
		{Name: "FIRST", Records: [][]byte{line("ONE"), line("TWO"), line("THREE")}},
		{Name: "EMPTY"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Blank([]string{"KEEP.SEQ"}); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 512)
	d.Source.ReadAt(header, 0)
	img, err := Compress(e, header, d.Heads, d.TrackSize)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := OpenCompressed(img)
	out, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	v, err := out.ReadVTOC(20)
	if err != nil {
		t.Fatal(err)
	}
	var pds, seq *Dataset
	for _, ds := range v.Datasets {
		switch ds.Name {
		case "NEW.PDS":
			pds = ds
		case "KEEP.SEQ":
			seq = ds
		}
	}
	ms, err := pds.Members(10)
	if err != nil || len(ms) != 2 || ms[0].Name != "EMPTY" || ms[1].Name != "FIRST" {
		t.Fatalf("members %+v %v", ms, err)
	}
	if ms[1].Track != 1 || ms[1].Record != 1 {
		t.Fatalf("FIRST at %d/%d", ms[1].Track, ms[1].Record)
	}
	content, err := pds.Content(&ms[1], 1000)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, content.Size())
	content.ReadAt(got, 0)
	want := append(append(line("ONE"), line("TWO")...), line("THREE")...)
	if !bytes.Equal(got, want) {
		t.Fatalf("FIRST content %q", got)
	}
	if empty, err := pds.Content(&ms[0], 1000); err != nil || empty.Size() != 0 {
		t.Fatalf("EMPTY content %v", err)
	}
	if lstar := pds.DSCB[98:101]; be.Uint16(lstar) != 2 || lstar[2] != 1 {
		t.Fatalf("DS1LSTAR %x", lstar)
	}
	rs, _ := seq.Track(0)
	if len(rs) != 2 || len(rs[1].Data) != 8 || !bytes.Equal(rs[1].Data, make([]byte, 8)) {
		t.Fatalf("blanked track %+v", rs)
	}
}

// Compact zeroes records no member reaches and leaves members intact.
func TestCompactZeroesDeadSpace(t *testing.T) {
	d, err := Open(raw(pdsFixture()))
	if err != nil {
		t.Fatal(err)
	}
	var tracks [][]Record
	for tr := uint32(0); tr < 12; tr++ {
		rs, _ := d.Track(tr)
		tracks = append(tracks, rs)
	}
	dir := make([]byte, 256)
	be.PutUint16(dir, 26)
	copy(dir[2:], eb("LIVE", 8))
	dir[10], dir[11], dir[12] = 0, 2, 1 // TTR: relative track 2, record 1
	copy(dir[14:], bytes.Repeat([]byte{0xff}, 8))
	tracks[8][1] = r(1, bytes.Repeat([]byte{0xff}, 8), dir)
	tracks[9] = append(tracks[9], r(1, nil, []byte("dead data")), r(2, nil, nil))
	tracks[10] = append(tracks[10], r(1, nil, []byte("live data")), r(2, nil, nil))
	dd := openTest(t, image(tracks))
	e, err := NewEdit(dd)
	if err != nil {
		t.Fatal(err)
	}
	dead, err := e.Compact([]string{"NEW.PDS"})
	if err != nil {
		t.Fatal(err)
	}
	if dead != 9 {
		t.Fatalf("dead bytes %d, want 9", dead)
	}
	if rs, _ := e.Track(9); !bytes.Equal(rs[1].Data, make([]byte, 9)) {
		t.Fatalf("dead record kept: %q", rs[1].Data)
	}
	if rs, _ := e.Track(10); string(rs[1].Data) != "live data" {
		t.Fatalf("live record changed: %q", rs[1].Data)
	}
	if rs, _ := e.Track(8); !bytes.Equal(rs[1].Data, dir) {
		t.Fatal("directory changed")
	}
}

// KeepMembers drops other members from the directory; Compact then zeroes
// their records.
func TestKeepMembers(t *testing.T) {
	d, err := Open(raw(pdsFixture()))
	if err != nil {
		t.Fatal(err)
	}
	var tracks [][]Record
	for tr := uint32(0); tr < 12; tr++ {
		rs, _ := d.Track(tr)
		tracks = append(tracks, rs)
	}
	dir := make([]byte, 256)
	be.PutUint16(dir, 2+3*12)
	copy(dir[2:], eb("A", 8))
	dir[11], dir[12] = 1, 1 // relative track 1, record 1
	copy(dir[14:], eb("B", 8))
	dir[23], dir[24] = 2, 1
	copy(dir[26:], bytes.Repeat([]byte{0xff}, 8))
	tracks[8][1] = r(1, bytes.Repeat([]byte{0xff}, 8), dir)
	tracks[9] = append(tracks[9], r(1, nil, []byte("member a")), r(2, nil, nil))
	tracks[10] = append(tracks[10], r(1, nil, []byte("member b")), r(2, nil, nil))
	e, err := NewEdit(openTest(t, image(tracks)))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.KeepMembers("NEW.PDS", []string{"B"}); err != nil {
		t.Fatal(err)
	}
	if dead, err := e.Compact([]string{"NEW.PDS"}); err != nil || dead != 8 {
		t.Fatalf("compact: %d dead bytes, %v", dead, err)
	}
	if rs, _ := e.Track(9); !bytes.Equal(rs[1].Data, make([]byte, 8)) {
		t.Fatalf("edit track 9: %q", rs[1].Data)
	}
	header := make([]byte, 512)
	e.Disk.Source.ReadAt(header, 0)
	img, err := Compress(e, header, e.Disk.Heads, e.Disk.TrackSize)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := OpenCompressed(img)
	out, _ := Open(c)
	v, _ := out.ReadVTOC(20)
	for _, ds := range v.Datasets {
		if ds.Name != "NEW.PDS" {
			continue
		}
		ms, err := ds.Members(10)
		if err != nil || len(ms) != 1 || ms[0].Name != "B" {
			t.Fatalf("members after keep: %+v %v", ms, err)
		}
		if rs, _ := ds.Track(1); !bytes.Equal(rs[1].Data, make([]byte, 8)) {
			t.Fatalf("removed member kept its data: %q", rs[1].Data)
		}
		if rs, _ := ds.Track(2); string(rs[1].Data) != "member b" {
			t.Fatalf("kept member changed: %q", rs[1].Data)
		}
		return
	}
	t.Fatal("NEW.PDS missing")
}

// A CKDZ image reads back as the same volume, null and duplicate tracks
// included, and opens through Open.
func TestCKDZRoundTrip(t *testing.T) {
	d := openTest(t, pdsFixture())
	e, err := NewEdit(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Remove([]string{"TEST.PDS"}); err != nil {
		t.Fatal(err)
	}
	if err := e.Blank([]string{"KEEP.SEQ"}); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 512)
	d.Source.ReadAt(header, 0)
	img, err := WriteCKDZ(e, header, d.Heads)
	if err != nil {
		t.Fatal(err)
	}
	if img.Held != e.Kept() || img.Dedup == 0 {
		t.Fatalf("held %d (kept %d), dedup %d", img.Held, e.Kept(), img.Dedup)
	}
	out, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	for tr := uint32(0); tr < e.Tracks(); tr++ {
		got, err := out.Track(tr)
		if err != nil {
			t.Fatalf("track %d: %v", tr, err)
		}
		var want []Record
		if e.Holds(tr) {
			want, _ = e.Track(tr)
		} else {
			want = []Record{{Number: 0, Data: make([]byte, 8)}, {Number: 1}}
		}
		if len(got) != len(want) {
			t.Fatalf("track %d: %d records, want %d", tr, len(got), len(want))
		}
		for i := range got {
			if got[i].Number != want[i].Number || !bytes.Equal(got[i].Key, want[i].Key) || !bytes.Equal(got[i].Data, want[i].Data) {
				t.Fatalf("track %d record %d differs", tr, i)
			}
		}
	}
	if v, err := out.ReadVTOC(20); err != nil || len(v.Datasets) != 2 {
		t.Fatalf("VTOC after CKDZ: %v", err)
	}
	if _, err := OpenCKDZ(&byteFile{bytes.NewReader(img.data[:600])}); err == nil {
		t.Fatal("opened a truncated image")
	}
}
