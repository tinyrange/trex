package ckd

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type cckdOptions struct {
	order     binary.ByteOrder
	nullFmt   byte
	raw       map[int]bool // tracks stored uncompressed
	null      map[int]bool // tracks stored as null level-2 entries
	nullL1    bool         // leave the final level-1 entry empty
	cylinders uint32
}

// trackImage returns the stored portion of a P370 track: home address through
// the end-of-track marker.
func trackImage(t testing.TB, track []byte) []byte {
	t.Helper()
	for p := 5; p+8 <= len(track); {
		if bytes.Equal(track[p:p+8], bytes.Repeat([]byte{255}, 8)) {
			return track[:p+8]
		}
		p += 8 + int(track[p+5]) + int(be.Uint16(track[p+6:]))
	}
	t.Fatal("fixture track has no end marker")
	return nil
}

// compressImage converts an uncompressed P370 fixture into a CCKD base image.
func compressImage(t testing.TB, p370 []byte, o cckdOptions) []byte {
	t.Helper()
	if o.order == nil {
		o.order = binary.LittleEndian
	}
	heads, size := le.Uint32(p370[8:]), int(le.Uint32(p370[12:]))
	tracks := (len(p370) - 512) / size
	if o.cylinders == 0 {
		o.cylinders = uint32(tracks) / heads
	}
	l1n := (tracks + 255) / 256
	if o.nullL1 {
		l1n++
	}
	out := make([]byte, 1024+4*l1n)
	copy(out, p370[:512])
	copy(out, "CKD_C370")
	ch := out[512:]
	ch[1], ch[2] = 2, 1
	if o.order == binary.BigEndian {
		ch[3] = 2
	}
	o.order.PutUint32(ch[4:], uint32(l1n))
	o.order.PutUint32(ch[8:], 256)
	o.order.PutUint32(ch[40:], o.cylinders)
	ch[44] = o.nullFmt
	ch[45] = 1
	l2s := make([][]byte, (tracks+255)/256)
	for i := range l2s {
		l2s[i] = make([]byte, 8*256)
	}
	var images []byte
	type loc struct{ track, offset, length int }
	var locs []loc
	for tr := 0; tr < tracks; tr++ {
		if o.null[tr] {
			continue
		}
		img := trackImage(t, p370[512+tr*size:512+(tr+1)*size])
		stored := append([]byte{}, img[:5]...)
		if o.raw[tr] {
			stored = append(stored, img[5:]...)
		} else {
			stored[0] = 1
			var z bytes.Buffer
			w := zlib.NewWriter(&z)
			w.Write(img[5:])
			w.Close()
			stored = append(stored, z.Bytes()...)
		}
		locs = append(locs, loc{tr, len(images), len(stored)})
		images = append(images, stored...)
	}
	base := len(out) + 8*256*len(l2s)
	for i := range l2s {
		o.order.PutUint32(out[1024+4*i:], uint32(len(out)+8*256*i))
	}
	for tr := range o.null {
		// Null entries record their format in both length and size.
		e := l2s[tr/256][8*(tr%256):]
		o.order.PutUint16(e[4:], uint16(o.nullFmt))
		o.order.PutUint16(e[6:], uint16(o.nullFmt))
	}
	for _, l := range locs {
		e := l2s[l.track/256][8*(l.track%256):]
		o.order.PutUint32(e, uint32(base+l.offset))
		o.order.PutUint16(e[4:], uint16(l.length))
		o.order.PutUint16(e[6:], uint16(l.length))
	}
	for _, l2 := range l2s {
		out = append(out, l2...)
	}
	return append(out, images...)
}

func readAll(t *testing.T, c *Compressed) []byte {
	t.Helper()
	b := make([]byte, c.Size())
	if _, err := c.ReadAt(b, 0); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCompressedMatchesUncompressed(t *testing.T) {
	p370 := fixture()
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		b := compressImage(t, p370, cckdOptions{order: order, raw: map[int]bool{2: true}})
		c, err := OpenCompressed(raw(b))
		if err != nil {
			t.Fatal(err)
		}
		got := readAll(t, c)
		want := append([]byte{}, p370...)
		copy(want, "CKD_P370")
		if !bytes.Equal(got, want) {
			t.Fatalf("%v: decoded image differs", order)
		}
		// Unaligned reads crossing header and track boundaries.
		part := make([]byte, 3*testTrackSize)
		if n, err := c.ReadAt(part, 500); n != len(part) || err != nil || !bytes.Equal(part, want[500:500+len(part)]) {
			t.Fatal("cross-track read", n, err)
		}
		if n, err := c.ReadAt(part, c.Size()-10); n != 10 || err != io.EOF {
			t.Fatal("EOF read", n, err)
		}
		// The ordinary CKD reader composes over the compressed image.
		d, err := Open(raw(b))
		if err != nil {
			t.Fatal(err)
		}
		v, err := d.ReadVTOC(20)
		if err != nil || v.Serial != "TEST01" || len(v.Datasets) != 1 {
			t.Fatal("VTOC", v, err)
		}
		if s, err := d.Walk(t.Context(), nil); err != nil || s.Tracks != 6 {
			t.Fatal("walk", s, err)
		}
	}
}

func TestCompressedNullTracks(t *testing.T) {
	p370 := fixture()
	for _, format := range []byte{0, 1} {
		// Track 5 is a null level-2 entry; the trailing level-1 entry and the
		// extra cylinder it describes are unallocated.
		b := compressImage(t, p370, cckdOptions{nullFmt: format, null: map[int]bool{5: true}, nullL1: true, cylinders: 129})
		c, err := OpenCompressed(raw(b))
		if err != nil {
			t.Fatal(err)
		}
		d, err := Open(c)
		if err != nil {
			t.Fatal(err)
		}
		// Null entries carry their own format, independent of the header's
		// default for missing level-2 tables.
		e := int(le.Uint32(b[1024:])) + 8*4
		le.PutUint32(b[e:], 0)
		le.PutUint16(b[e+4:], 1)
		le.PutUint16(b[e+6:], 1)
		// An all-ones null entry is a null track in the header's format.
		e3 := int(le.Uint32(b[1024:])) + 8*3
		le.PutUint32(b[e3:], 0)
		le.PutUint16(b[e3+4:], 0xffff)
		le.PutUint16(b[e3+6:], 0xffff)
		if rs, err := d.Track(3); err != nil || len(rs) != 2-int(format) || rs[0].Number != 0 {
			t.Fatalf("all-ones null entry: %+v %v", rs, err)
		}
		if rs, err := d.Track(4); err != nil || len(rs) != 1 || rs[0].Number != 0 {
			t.Fatalf("per-entry null format: %+v %v", rs, err)
		}
		for _, track := range []uint32{5, 256, 257} {
			rs, err := d.Track(track)
			if err != nil {
				t.Fatal(track, err)
			}
			if len(rs) != 2-int(format) || rs[0].Number != 0 || len(rs[0].Data) != 8 {
				t.Fatalf("format %d track %d: %+v", format, track, rs)
			}
			if format == 0 && (rs[1].Number != 1 || len(rs[1].Data) != 0 || rs[1].Cylinder != uint16(track/2)) {
				t.Fatalf("EOF record %+v", rs[1])
			}
		}
		if _, err := d.Track(258); err == nil {
			t.Fatal("read past declared cylinders")
		}
	}
}

func TestCompressedRejectsMalformed(t *testing.T) {
	p370 := fixture()
	original := compressImage(t, p370, cckdOptions{raw: map[int]bool{2: true}})
	l1 := int(le.Uint32(original[1024:]))
	entry := func(tr int) int { return l1 + 8*tr }
	pos := func(b []byte, tr int) int { return int(le.Uint32(b[entry(tr):])) }
	cases := map[string]func([]byte){
		"signature":      func(b []byte) { copy(b, "CKD_S370") },
		"geometry":       func(b []byte) { le.PutUint32(b[8:], 0) },
		"version":        func(b []byte) { b[512] = 1 },
		"level2-size":    func(b []byte) { le.PutUint32(b[520:], 128) },
		"cylinders":      func(b []byte) { le.PutUint32(b[552:], 1000) },
		"null-format":    func(b []byte) { b[556] = 2 },
		"shadow-level1":  func(b []byte) { le.PutUint32(b[1024:], 0xffffffff) },
		"level1-range":   func(b []byte) { le.PutUint32(b[1024:], uint32(len(b))) },
		"allocation":     func(b []byte) { le.PutUint16(b[entry(1)+6:], 1) },
		"null-length":    func(b []byte) { le.PutUint32(b[entry(1):], 0) },
		"extent":         func(b []byte) { le.PutUint32(b[entry(1):], uint32(len(b))) },
		"address":        func(b []byte) { b[pos(b, 1)+4] ^= 1 },
		"compression":    func(b []byte) { b[pos(b, 1)] = 2 },
		"zlib-checksum":  func(b []byte) { b[pos(b, 1)+int(le.Uint16(b[entry(1)+4:]))-1] ^= 1 },
		"raw-end-marker": func(b []byte) { b[pos(b, 2)+int(le.Uint16(b[entry(2)+4:]))-1] = 0 },
		"trailing-stream": func(b []byte) {
			le.PutUint16(b[entry(1)+4:], le.Uint16(b[entry(1)+4:])+1)
			le.PutUint16(b[entry(1)+6:], le.Uint16(b[entry(1)+6:])+1)
		},
		"raw-oversize": func(b []byte) {
			le.PutUint16(b[entry(2)+4:], testTrackSize+1)
			le.PutUint16(b[entry(2)+6:], testTrackSize+1)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := bytes.Clone(original)
			mutate(b)
			c, err := OpenCompressed(raw(b))
			if err == nil {
				_, err = c.ReadAt(make([]byte, c.Size()), 0)
			}
			if err == nil {
				t.Fatal("accepted malformed CCKD image")
			}
		})
	}
	// A decompressed image larger than the track size must fail.
	big := bytes.Clone(original)
	le.PutUint32(big[12:], 64)
	if c, err := OpenCompressed(raw(big)); err == nil {
		if _, err := c.ReadAt(make([]byte, c.Size()), 0); err == nil {
			t.Fatal("accepted oversized track")
		}
	}
	for n := 0; n < len(original); n += 7 {
		c, err := OpenCompressed(raw(original[:n]))
		if err == nil {
			_, err = c.ReadAt(make([]byte, c.Size()), 0)
		}
		if err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
}

func FuzzCompressed(f *testing.F) {
	f.Add([]byte{})
	f.Add(compressImage(f, fixture(), cckdOptions{raw: map[int]bool{2: true}}))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := OpenCompressed(raw(data))
		if err != nil || c.Size() > 1<<24 {
			return
		}
		_, _ = c.ReadAt(make([]byte, c.Size()), 0)
	})
}

func TestScanReportsTrackErrors(t *testing.T) {
	b := compressImage(t, fixture(), cckdOptions{})
	e := int(le.Uint32(b[1024:])) + 8
	pos, length := int(le.Uint32(b[e:])), int(le.Uint16(b[e+4:]))
	b[pos+length-1] ^= 1 // break track 1's zlib checksum
	file := starfile.NewReader("damaged.cckd", raw(b))
	if _, err := ScanBuiltin(nil, nil, starlark.Tuple{file}, nil); err == nil {
		t.Fatal("strict scan accepted damaged track")
	}
	v, err := ScanBuiltin(nil, nil, starlark.Tuple{file}, []starlark.Tuple{{starlark.String("max_errors"), starlark.MakeInt(1)}})
	if err != nil {
		t.Fatal(err)
	}
	tracks, _ := v.(starlark.HasAttrs).Attr("tracks")
	errs, _ := v.(starlark.HasAttrs).Attr("errors")
	if tracks != starlark.MakeInt(5) || errs.(*starlark.List).Len() != 1 {
		t.Fatal(tracks, errs)
	}
	track, _ := errs.(*starlark.List).Index(0).(starlark.HasAttrs).Attr("track")
	if track != starlark.MakeInt(1) {
		t.Fatal("wrong failing track", track)
	}
	e2 := e + 8
	b[int(le.Uint32(b[e2:]))+int(le.Uint16(b[e2+4:]))-1] ^= 1 // also break track 2
	if _, err := ScanBuiltin(nil, nil, starlark.Tuple{starfile.NewReader("damaged.cckd", raw(b))}, []starlark.Tuple{{starlark.String("max_errors"), starlark.MakeInt(1)}}); err == nil {
		t.Fatal("exceeded max_errors silently")
	}
}
