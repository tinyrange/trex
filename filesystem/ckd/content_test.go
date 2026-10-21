package ckd

import (
	"bytes"
	"io"
	"testing"

	"github.com/tinyrange/trex/auto"
)

func TestSequentialContentPreservesBlockHeaders(t *testing.T) {
	// A VB block and a second block on another track, followed by EOF and stale
	// trailing bytes. The reader must neither strip headers nor include stale data.
	first := []byte{0, 9, 0, 0, 0, 5, 0, 0, 'A'}
	second := []byte{0, 9, 0, 0, 0, 5, 0, 0, 'B'}
	d := openTest(t, image([][]Record{{r(0, nil, make([]byte, 8)), r(1, nil, first)}, {r(0, nil, make([]byte, 8)), r(1, nil, second), r(2, nil, nil), r(3, nil, []byte("deleted"))}}))
	ds := &Dataset{Disk: d, Name: "SEQ", Organization: 0x4000, RecordFormat: 0x50, Extents: []Extent{{First: 0, Last: 1}}}
	c, e := ds.Content(nil, 10)
	if e != nil {
		t.Fatal(e)
	}
	p, e := io.ReadAll(io.NewSectionReader(c, 0, c.Size()))
	if e != nil || !bytes.Equal(p, append(first, second...)) {
		t.Fatalf("%x %v", p, e)
	}
	for _, flag := range []byte{2, 4, 8} {
		ds.SMSFlags = flag
		if _, e := ds.Content(nil, 10); e == nil {
			t.Fatal("unsupported organization accepted", flag)
		}
	}
	ds.SMSFlags = 0
	ds.Flags = 0x80
	if _, e := ds.Content(nil, 10); e == nil {
		t.Fatal("large/extended dataset accepted")
	}
	ds.Flags = 0
	ds.Extents[0].Last = 0
	if _, e := ds.Content(nil, 10); e == nil {
		t.Fatal("missing EOF accepted")
	}
}
func TestRawTrackAutoAccessAndMissingTerminator(t *testing.T) {
	b := fixture()
	n := auto.Open(raw(b), "disk", auto.Options{})
	label, e := n.Resolve("tracks/00000/000/001-r003.data")
	if e != nil {
		t.Fatal(e)
	}
	m, e := label.Metadata()
	if e != nil {
		t.Fatal(e)
	}
	if m.Size != 80 {
		t.Fatal(m)
	}
	data := make([]byte, 4)
	if _, e := label.Reader().ReadAt(data, 0); e != nil || Identifier(data) != "VOL1" {
		t.Fatal(data, e)
	}
	rs, e := openTest(t, b).Track(0)
	if e != nil {
		t.Fatal(e)
	}
	last := rs[len(rs)-1]
	pos := int(last.Offset) + 8 + len(last.Key) + len(last.Data)
	copy(b[pos:pos+8], make([]byte, 8))
	if _, e := openTest(t, b).Track(0); e == nil {
		t.Fatal("missing end marker accepted")
	}
}
