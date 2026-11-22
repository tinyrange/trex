package scsi

import (
	"encoding/binary"
	"testing"
)

func TestOpticalModeSenseParametersAndMasks(t *testing.T) {
	d, err := NewOptical(make(disc, 2048))
	if err != nil {
		t.Fatal(err)
	}
	run := func(c []byte) Result {
		t.Helper()
		r, e := d.Execute(c)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	c := []byte{0x5a, 8, 0x7f, 0, 0, 0, 0, 0x10, 0, 0}
	r := run(c)
	if r.Status != 0 || len(r.Data) != 42 || binary.BigEndian.Uint16(r.Data) != 40 || r.Data[3] != 0x80 || binary.BigEndian.Uint16(r.Data[6:8]) != 0 {
		t.Fatalf("mode10 header: %x", r.Data)
	}
	for at := 8; at < len(r.Data); {
		p := r.Data[at : at+2+int(r.Data[at+1])]
		for _, v := range p[2:] {
			if v != 0 {
				t.Fatal("immutable page has changeable bits")
			}
		}
		at += len(p)
	}
	c[2] = 0x2a
	r = run(c)
	if r.Data[10] != 8 || r.Data[11] != 0 || r.Data[14] != 0x29 {
		t.Fatalf("capabilities advertise unimplemented media operations: %x", r.Data)
	}
	run([]byte{0x1e, 0, 0, 0, 1, 0})
	if run(c).Data[14] != 0x2b {
		t.Fatal("mechanical status lost actual prevent-removal state")
	}
	c[8] = 5
	c[7] = 0
	r = run(c)
	if len(r.Data) != 5 || binary.BigEndian.Uint16(r.Data) != 28 {
		t.Fatal("allocation limit changed complete parameter length")
	}
	r = run([]byte{0x1a, 8, 0x2a, 0, 255, 0})
	if len(r.Data) != 26 || r.Data[0] != 25 || r.Data[2] != 0x80 || r.Data[4] != 0x2a {
		t.Fatal("mode6 framing")
	}
	for _, page := range []byte{0xc0 | 0x2a, 0x1f} {
		c[2] = page
		if r = run(c); r.Status != 2 || r.Sense[2] != 5 {
			t.Fatal("unsupported saved values/page accepted")
		}
	}
}
