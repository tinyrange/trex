package ckd

import (
	"bytes"
	"io"
	"testing"
)

func TestPagesFragmentedAllocation(t *testing.T) {
	track := func(a, b byte) []Record {
		return []Record{r(0, nil, make([]byte, 8)), r(1, nil, bytes.Repeat([]byte{a}, 512)), r(2, nil, bytes.Repeat([]byte{b}, 512))}
	}
	d := openTest(t, image([][]Record{track(1, 2), track(9, 9), track(0, 4)}))
	ds := &Dataset{Disk: d, Extents: []Extent{{First: 2, Last: 2}, {First: 0, Last: 0}}}
	p, err := ds.OpenPages(512)
	if err != nil {
		t.Fatal(err)
	}
	if p.Count() != 4 || p.Size() != 2048 {
		t.Fatal(p.Count(), p.Size())
	}
	want := append(make([]byte, 512), bytes.Repeat([]byte{4}, 512)...)
	want = append(want, bytes.Repeat([]byte{1}, 512)...)
	want = append(want, bytes.Repeat([]byte{2}, 512)...)
	got := make([]byte, 2050)
	n, err := p.ReadAt(got, 0)
	if n != 2048 || err != io.EOF || !bytes.Equal(got[:n], want) {
		t.Fatalf("allocation read n=%d err=%v", n, err)
	}
	page, err := p.Page(0)
	if err != nil || !bytes.Equal(page, make([]byte, 512)) {
		t.Fatal("zero page lost", err)
	}
	if _, err := p.Page(4); err == nil {
		t.Fatal("out-of-range page accepted")
	}
	if _, err := p.ReadAt(got, -1); err == nil {
		t.Fatal("negative offset accepted")
	}
	if n, err := p.ReadAt(nil, p.Size()); n != 0 || err != nil {
		t.Fatal(n, err)
	}
}

func TestPagesRejectInconsistentTracks(t *testing.T) {
	good := []Record{r(1, nil, make([]byte, 512)), r(2, nil, make([]byte, 512))}
	for _, bad := range [][]Record{
		{r(2, nil, make([]byte, 512))},
		{r(1, nil, make([]byte, 512)), r(2, nil, make([]byte, 511))},
		{r(1, nil, make([]byte, 512)), r(2, []byte{1}, make([]byte, 512))},
	} {
		ds := &Dataset{Disk: openTest(t, image([][]Record{good, bad})), Extents: []Extent{{First: 0, Last: 1}}}
		p, err := ds.OpenPages(512)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Page(2); err == nil {
			t.Fatal("invalid later track accepted")
		}
		if _, err := p.Page(0); err != nil {
			t.Fatal(err)
		}
	}
	ds := &Dataset{Disk: openTest(t, image([][]Record{{r(1, nil, make([]byte, 511))}})), Extents: []Extent{{First: 0, Last: 0}}}
	if _, err := ds.OpenPages(512); err == nil {
		t.Fatal("invalid first track accepted")
	}
}
