package ckd

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	nativegzip "github.com/tinyrange/trex/archive/gzip"
	"github.com/tinyrange/trex/auto"
)

const testTrackSize = 2048

func image(tracks [][]Record) []byte {
	b := make([]byte, 512+testTrackSize*len(tracks))
	copy(b, "CKD_P370")
	le.PutUint32(b[8:], 2)
	le.PutUint32(b[12:], testTrackSize)
	b[16] = 0x90
	for t, rs := range tracks {
		p := 512 + t*testTrackSize
		be.PutUint16(b[p+1:], uint16(t/2))
		be.PutUint16(b[p+3:], uint16(t%2))
		p += 5
		for _, r := range rs {
			be.PutUint16(b[p:], uint16(t/2))
			be.PutUint16(b[p+2:], uint16(t%2))
			b[p+4] = r.Number
			b[p+5] = byte(len(r.Key))
			be.PutUint16(b[p+6:], uint16(len(r.Data)))
			copy(b[p+8:], r.Key)
			copy(b[p+8+len(r.Key):], r.Data)
			p += 8 + len(r.Key) + len(r.Data)
		}
		copy(b[p:], bytes.Repeat([]byte{255}, 8))
	}
	return b
}
func openTest(t *testing.T, b []byte) *Disk {
	t.Helper()
	d, e := Open(raw(b))
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func r(n byte, key, data []byte) Record { return Record{Number: n, Key: key, Data: data} }
func eb(s string, n int) []byte {
	b := bytes.Repeat([]byte{0x40}, n)
	for i, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'I':
			b[i] = c - 'A' + 0xc1
		case c >= 'J' && c <= 'R':
			b[i] = c - 'J' + 0xd1
		case c >= 'S' && c <= 'Z':
			b[i] = c - 'S' + 0xe2
		case c >= '0' && c <= '9':
			b[i] = c - '0' + 0xf0
		case c == '.':
			b[i] = 0x4b
		default:
			panic("fixture encoding")
		}
	}
	return b
}
func address(p []byte, t uint16) { be.PutUint16(p, t/2); be.PutUint16(p[2:], t%2) }
func extent(p []byte, seq byte, a, b uint16) {
	p[0] = 1
	p[1] = seq
	address(p[2:], a)
	address(p[6:], b)
}
func fixture() []byte {
	label := make([]byte, 80)
	copy(label, eb("VOL1", 4))
	copy(label[4:], eb("TEST01", 6))
	address(label[11:], 1)
	label[15] = 1
	f4 := make([]byte, 140)
	copy(f4, bytes.Repeat([]byte{4}, 44))
	f4[44] = 0xf4
	f4[59] = 1
	extent(f4[105:], 0, 1, 1)
	f1 := make([]byte, 140)
	copy(f1, eb("TEST.PDS", 44))
	f1[44] = 0xf1
	copy(f1[45:], eb("TEST01", 6))
	f1[52] = 1
	f1[59] = 4
	f1[82] = 2
	f1[84] = 0x90
	be.PutUint16(f1[88:], 80)
	// Logical extent order differs from physical order; continuation is necessary.
	extent(f1[105:], 0, 2, 2)
	extent(f1[115:], 1, 4, 4)
	extent(f1[125:], 2, 3, 3)
	address(f1[135:], 1)
	f1[139] = 3
	f3 := make([]byte, 140)
	copy(f3, []byte{3, 3, 3, 3})
	f3[44] = 0xf3
	extent(f3[4:], 3, 5, 5)
	directory := make([]byte, 256)
	be.PutUint16(directory, 34)
	copy(directory[2:], eb("ALIAS", 8))
	directory[12] = 2
	directory[13] = 128
	copy(directory[14:], eb("MEMBER", 8))
	directory[24] = 2
	copy(directory[26:], bytes.Repeat([]byte{255}, 8))
	return image([][]Record{
		{r(0, nil, make([]byte, 8)), r(3, eb("VOL1", 4), label)},
		{r(0, nil, make([]byte, 8)), r(1, f4[:44], f4[44:]), r(2, f1[:44], f1[44:]), r(3, f3[:44], f3[44:])},
		{r(0, nil, make([]byte, 8)), r(1, nil, directory), r(2, []byte("KEY"), []byte("first"))},
		{r(0, nil, make([]byte, 8)), r(1, nil, nil)},
		{r(0, nil, make([]byte, 8)), r(1, nil, []byte("second"))},
		{r(0, nil, make([]byte, 8))},
	})
}
func TestVTOCExtentsPDSAndRanges(t *testing.T) {
	b := fixture()
	d := openTest(t, b)
	v, e := d.ReadVTOC(20)
	if e != nil {
		t.Fatal(e)
	}
	if v.Serial != "TEST01" || len(v.Datasets) != 1 {
		t.Fatalf("bad volume %+v", v)
	}
	ds := v.Datasets[0]
	if len(ds.Extents) != 4 || ds.Extents[3].First != 5 {
		t.Fatalf("bad extents %v", ds.Extents)
	}
	ms, e := ds.Members(10)
	if e != nil {
		t.Fatal(e)
	}
	if len(ms) != 2 || !ms[0].Alias || ms[1].Alias {
		t.Fatalf("bad members %+v", ms)
	}
	for _, m := range ms {
		c, e := ds.Content(&m, 10)
		if e != nil {
			t.Fatal(e)
		}
		p, e := io.ReadAll(io.NewSectionReader(c, 0, c.Size()))
		if e != nil || string(p) != "firstsecond" {
			t.Fatalf("content %q: %v", p, e)
		}
		buf := make([]byte, 8)
		n, e := c.ReadAt(buf, 3)
		if e != nil || n != 8 || string(buf) != "stsecond" {
			t.Fatalf("cross-block %q %d %v", buf, n, e)
		}
		n, e = c.ReadAt(buf, 10)
		if n != 1 || e != io.EOF || buf[0] != 'd' {
			t.Fatalf("EOF %d %v", n, e)
		}
		if n, e := c.ReadAt(nil, c.Size()); n != 0 || e != nil {
			t.Fatal(n, e)
		}
		if _, e := c.ReadAt(buf, -1); e == nil {
			t.Fatal("negative read accepted")
		}
	}
	a := ds.Allocation()
	if a.Size() != 4*testTrackSize {
		t.Fatal(a.Size())
	}
	buf := make([]byte, 20)
	if _, e := a.ReadAt(buf, testTrackSize-10); e != nil {
		t.Fatal(e)
	}
	want := append(bytes.Clone(b[512+3*testTrackSize-10:512+3*testTrackSize]), b[512+4*testTrackSize:512+4*testTrackSize+10]...)
	if !bytes.Equal(buf, want) {
		t.Fatal("allocation range ignored extent order")
	}
	stats, e := d.Walk(context.Background(), nil)
	if e != nil || stats.Tracks != 6 || stats.ImageBytes != int64(len(b)) {
		t.Fatalf("walk %+v %v", stats, e)
	}
}
func TestMalformedDiskAndGzip(t *testing.T) {
	b := fixture()
	for _, n := range []int{0, 7, 511, 512 + testTrackSize - 1, len(b) - 1} {
		t.Run(string(rune('A'+n%26)), func(t *testing.T) {
			d, e := Open(raw(b[:n]))
			if e == nil {
				_, e = d.Walk(context.Background(), nil)
			}
			if e == nil {
				t.Fatalf("accepted truncated image %d", n)
			}
		})
	}
	for _, offset := range []int{0, 8, 12} {
		bad := bytes.Clone(b)
		for i := 0; i < 4; i++ {
			bad[offset+i] = 0
		}
		if _, e := Open(raw(bad)); e == nil {
			t.Fatal("bad header accepted", offset)
		}
	}
	bad := bytes.Clone(b)
	bad[512+1] = 1
	if _, e := openTest(t, bad).Track(0); e == nil {
		t.Fatal("bad home address accepted")
	}
	bad = bytes.Clone(b)
	bad[512+5+6] = 255
	bad[512+5+7] = 255
	if _, e := openTest(t, bad).Track(0); e == nil {
		t.Fatal("oversized record accepted")
	}
	bad = bytes.Clone(b)
	bad[512+5] = 0x12
	bad[512+5+1] = 0x34
	rs, e := openTest(t, bad).Track(0)
	if e != nil || rs[0].Cylinder != 0x1234 {
		t.Fatal("nonphysical count address lost", e)
	}
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	w.Write(b)
	w.Close()
	compressed.Bytes()[compressed.Len()-8] ^= 1
	g, e := nativegzip.Open(raw(compressed.Bytes()), 0)
	if e != nil {
		t.Fatal(e)
	}
	d, e := Open(g)
	if e == nil {
		_, e = d.Walk(context.Background(), nil)
	}
	if e == nil {
		t.Fatal("gzip checksum failure hidden")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := openTest(t, b).Walk(ctx, nil); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestMalformedVTOCAndPDS(t *testing.T) {
	d := openTest(t, fixture())
	if _, e := d.ReadVTOC(2); e == nil {
		t.Fatal("DSCB limit ignored")
	}
	v, e := d.ReadVTOC(20)
	if e != nil {
		t.Fatal(e)
	}
	ds := v.Datasets[0]
	if _, e := ds.Members(1); e == nil {
		t.Fatal("member limit ignored")
	}
	if _, e := ds.Content(&Member{Track: 0, Record: 200}, 10); e == nil {
		t.Fatal("missing record accepted")
	}
	if _, e := ds.Content(&Member{Track: 0, Record: 2}, 1); e == nil {
		t.Fatal("record limit ignored")
	}
	ds.SMSFlags = 8
	if _, e := ds.Members(20); e == nil {
		t.Fatal("PDSE treated as PDS")
	}
	ds.SMSFlags = 2
	if ds.IsPDS() {
		t.Fatal("HFS treated as PDS")
	}
	for _, b := range [][]byte{nil, make([]byte, 255), make([]byte, 256)} {
		if _, _, e := DirectoryBlock(b); e == nil {
			t.Fatal("bad directory accepted")
		}
	}
	b := make([]byte, 256)
	be.PutUint16(b, 14)
	b[13] = 31
	if _, _, e := DirectoryBlock(b); e == nil {
		t.Fatal("overlong user data accepted")
	}
	// Point the continuation to the format-3 record itself, rather than ending it.
	b = fixture()
	off := 512 + testTrackSize + 5 + 16 + 148 + 148 + 8 + 135
	address(b[off:], 1)
	b[off+4] = 3
	if _, e := openTest(t, b).ReadVTOC(20); e == nil || !strings.Contains(e.Error(), "cyclic") {
		t.Fatal("cyclic chain not diagnosed", e)
	}
}
func TestAutoNestedPDS(t *testing.T) {
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	w.Write(fixture())
	w.Close()
	n := auto.Open(raw(compressed.Bytes()), "disk.gz", auto.Options{})
	// gzip transparently enters the CKD volume through normal auto browsing.
	for _, name := range []string{"datasets", "TEST.PDS", "members", "MEMBER", "data.bin"} {
		children, e := n.Children()
		if e != nil {
			t.Fatal(name, e)
		}
		var next *auto.Node
		for _, c := range children {
			if c.Name() == name {
				next = c
				break
			}
		}
		if next == nil {
			t.Fatalf("missing %s", name)
		}
		n = next
	}
	r := n.Reader()
	b, e := io.ReadAll(io.NewSectionReader(r, 0, r.Size()))
	if e != nil || string(b) != "firstsecond" {
		t.Fatalf("%q %v", b, e)
	}
}

func TestVTOCScanBudgetIsNotBrowserEntryBudget(t *testing.T) {
	// One dataset resides among three DSCBs. The CKD dataset budget must
	// not become the physical VTOC slot budget. Test the view directly;
	// auto applies its separate entry cap to synthetic metadata entries too.
	root, e := openTest(t, fixture()).View(1).Entries()
	if e != nil {
		t.Fatal(e)
	}
	entries, e := root[0].View.Entries()
	if e != nil {
		t.Fatal(e)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries including volume metadata", len(entries))
	}
	// Duplicate physical addresses must not silently overwrite the DSCB index.
	b := fixture()
	off := 512 + testTrackSize + 5 + 16 + 148 + 148
	b[off+4] = 2
	if _, e := openTest(t, b).ReadVTOC(20); e == nil || !strings.Contains(e.Error(), "duplicate DSCB") {
		t.Fatal(e)
	}
}
