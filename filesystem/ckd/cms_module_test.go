package ckd

import (
	"bytes"
	"testing"
)

type moduleSpec struct {
	entry, origin  uint32
	image          []byte
	coreSplit      []int    // core record lengths
	loader         []string // loader entry names
	loaderSize     int      // 20 or 24
	relocations    []uint32 // addresses
	width          int      // 0 (none), 4 or 5
	extra          [][]byte // records after the relocation list
	trailerSplit   []int    // lengths splitting loader+relocation bytes
	programObjects bool
}

func vstream(records ...[]byte) []byte {
	var out []byte
	for _, r := range records {
		out = append(out, byte(len(r)>>8), byte(len(r)))
		out = append(out, r...)
	}
	return out
}

func (s moduleSpec) records() [][]byte {
	h := make([]byte, 80)
	be.PutUint32(h, s.entry)
	be.PutUint32(h[4:], s.origin)
	be.PutUint32(h[8:], s.origin+uint32(len(s.image)))
	be.PutUint32(h[12:], s.origin+uint32(len(s.image)))
	be.PutUint16(h[0x28:], uint16(len(s.loader)))
	switch s.width {
	case 4:
		h[0x2d] = 0x90
	case 5:
		h[0x2d] = 0xd0
	}
	records := [][]byte{h}
	p := 0
	for _, n := range s.coreSplit {
		records = append(records, s.image[p:p+n])
		p += n
	}
	var trailer []byte
	if s.programObjects {
		trailer = append(append([]byte{}, cmsProgramObject...), 0, 1, 2)
	}
	for _, name := range s.loader {
		e := make([]byte, s.loaderSize)
		copy(e, eb(name, 8))
		be.PutUint32(e[8:], s.origin)
		trailer = append(trailer, e...)
	}
	for _, a := range s.relocations {
		if s.width == 4 {
			trailer = append(trailer, 0x03, byte(a>>16), byte(a>>8), byte(a))
		} else {
			trailer = append(trailer, 0x83, byte(a>>24), byte(a>>16), byte(a>>8), byte(a))
		}
	}
	q := 0
	for _, n := range s.trailerSplit {
		records = append(records, trailer[q:q+n])
		q += n
	}
	if q < len(trailer) {
		records = append(records, trailer[q:])
	}
	return append(records, s.extra...)
}

func TestCMSModuleSegments(t *testing.T) {
	image := bytes.Repeat([]byte{0x47, 0xf0, 0, 0}, 100) // 400 bytes
	text := card(eb("SERVICE", 7))
	a := moduleSpec{entry: 0x20018, origin: 0x20010, image: image, coreSplit: []int{150, 250},
		loader: []string{"MAIN", "SYSREF", "NUCON"}, loaderSize: 24, relocations: []uint32{0x20010, 0x2019c, 0x20008}, width: 4,
		trailerSplit: []int{30, 42}, extra: [][]byte{text, text}}
	m, err := ParseCMSModule(vstream(a.records()...), true, 1000)
	if err != nil {
		t.Fatal(err)
	}
	s := m.Segments[0]
	if len(m.Segments) != 1 || !bytes.Equal(s.Image, image) || s.Entry != 0x20018 || len(s.LoaderTable) != 3 || s.LoaderTable[1].Name != "SYSREF" || len(s.LoaderTable[0].Words) != 4 {
		t.Fatalf("segment %+v", s)
	}
	if s.RelocationWidth != 4 || len(s.Relocations) != 3 || s.Relocations[2].Address != 0x20008 || !bytes.Equal(s.Extra, append(append([]byte{}, text...), text...)) {
		t.Fatalf("relocations %+v extra %q", s.Relocations, s.Extra)
	}
	// 20-byte loader entries, 5-byte relocations above 16 MiB, then a second
	// segment whose header is an 80-byte record inside the trailer.
	b := moduleSpec{entry: 0x81f00000, origin: 0x1f00000, image: image[:200], coreSplit: []int{200},
		loader: []string{"OLDMOD", "SYSREF"}, loaderSize: 20, relocations: []uint32{0x1f00004, 0x1f00010, 0x1f00020}, width: 5, trailerSplit: []int{55}}
	c := moduleSpec{entry: 0x2000, origin: 0x2000, image: image[:96], coreSplit: []int{96}, relocations: []uint32{0x2000, 0x2004}, width: 5}
	m, err = ParseCMSModule(vstream(append(b.records(), c.records()...)...), true, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Segments) != 2 || len(m.Segments[0].LoaderTable) != 2 || len(m.Segments[0].LoaderTable[0].Words) != 3 || len(m.Segments[0].Relocations) != 3 || m.Segments[1].Origin != 0x2000 || len(m.Segments[1].Relocations) != 2 {
		t.Fatalf("two segments %+v", m.Segments)
	}
	// No relocation list: trailer bytes after the loader table are Extra.
	d := moduleSpec{origin: 0x10000, image: image[:8], coreSplit: []int{8}, loader: []string{"X"}, loaderSize: 24, extra: [][]byte{text}}
	if m, err = ParseCMSModule(vstream(d.records()...), true, 1000); err != nil || m.Segments[0].RelocationWidth != 0 || !bytes.Equal(m.Segments[0].Extra, text) {
		t.Fatal("no relocation list", err)
	}
	e := moduleSpec{origin: 0x10000, image: image[:8], coreSplit: []int{8}, programObjects: true}
	if m, err = ParseCMSModule(vstream(e.records()...), true, 1000); err != nil || m.Segments[0].ProgramObject == nil {
		t.Fatal("program object", err)
	}
	if m, err = ParseCMSModule(image, false, 1); err != nil || m.Segments[0].Header != nil || !bytes.Equal(m.Segments[0].Image, image) {
		t.Fatal("fixed module", err)
	}

	bad := map[string][][]byte{}
	short := a
	short.coreSplit = []int{150, 200}
	bad["core-short"] = short.records()
	mid := a
	mid.extra = nil
	mid.trailerSplit = nil
	rs := mid.records()
	rs[len(rs)-1] = append(rs[len(rs)-1], text...) // text inside the relocation record
	bad["extra-mid-record"] = rs
	names := a
	names.loader = []string{"MAIN", "SYSREF", "NUCON"}
	rs = names.records()
	rs[3][24] = 0x01 // second loader name
	bad["loader-name"] = rs
	bad["header"] = [][]byte{make([]byte, 79)}
	for name, records := range bad {
		if _, err := ParseCMSModule(vstream(records...), true, 1000); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseCMSModule(vstream(a.records()...), true, 4); err == nil {
		t.Error("ignored entry limit")
	}
}

func TestUnpackCMSVariableContainer(t *testing.T) {
	// A V-format packed stream in container records, using the 16-bit final
	// literal; the final container's tail repeats the stream 1024 bytes back.
	body := bytes.Repeat([]byte("L"), 300)
	stream := packed(0xe5, 400, append([]byte{0xfd, 0x01, 0x2b}, body...), bytes.Repeat([]byte{0x7c, 0x00}, 400))
	for len(stream) < 1500 {
		stream = append(stream, 0x7c, 0x00)
	}
	end := len(stream)
	stream = append(stream, 0xff)
	stream = append(stream, stream[end+1-1024:end+1-1024+47]...)
	records := [][]byte{stream[:1024], stream[1024:]}
	u, err := UnpackCMSRecords(records, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if u.Records != 1+(end-8-303)/2 || u.MaximumRecord != 300 || !bytes.Equal(u.Data[2:302], body) {
		t.Fatalf("records %d max %d", u.Records, u.MaximumRecord)
	}
	records[1] = append(records[1][:len(records[1])-1], 0x01)
	if _, err := UnpackCMSRecords(records, 1<<20); err == nil {
		t.Fatal("accepted a tail that is neither blank nor stale")
	}
}

func FuzzParseCMSModule(f *testing.F) {
	image := bytes.Repeat([]byte{0x47}, 64)
	a := moduleSpec{origin: 0x20000, image: image, coreSplit: []int{64}, loader: []string{"A"}, loaderSize: 24, relocations: []uint32{0x20000}, width: 4}
	f.Add(vstream(a.records()...))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseCMSModule(b, true, 1000)
	})
}
