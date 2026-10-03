package ckd

import "testing"

func TestPagesPartialTrackDoesNotShiftAddresses(t *testing.T) {
	data := func(v byte) []byte { b := make([]byte, 512); b[0] = v; return b }
	d := openTest(t, image([][]Record{
		{r(1, nil, data(1)), r(2, nil, data(2))},
		{r(1, nil, data(3))},
		{r(1, nil, data(5)), r(2, nil, data(6))},
	}))
	ds := &Dataset{Disk: d, Extents: []Extent{{First: 0, Last: 1}, {First: 2, Last: 2}}}
	p, err := ds.OpenPages(512)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []uint64{2, 4, 5} {
		b, err := p.Page(index)
		if err != nil || b[0] != byte(index+1) {
			t.Fatal(index, err)
		}
	}
	if _, err := p.Page(3); err == nil {
		t.Fatal("missing slot silently filled")
	}
	b := make([]byte, 1024)
	if n, err := p.ReadAt(b, 1024); n != 512 || err == nil {
		t.Fatal(n, err)
	}
}
