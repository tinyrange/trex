package scsi

import (
	"encoding/binary"
	"testing"
)

func TestOpticalConfigurationFilteringAndMediaState(t *testing.T) {
	d, err := NewOptical(make(disc, 2048))
	if err != nil {
		t.Fatal(err)
	}
	query := func(rt byte, start uint16, n uint16) Result {
		t.Helper()
		c := make([]byte, 10)
		c[0], c[1] = 0x46, rt
		binary.BigEndian.PutUint16(c[2:4], start)
		binary.BigEndian.PutUint16(c[7:9], n)
		r, e := d.Execute(c)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	r := query(0, 0, 2048)
	if r.Status != 0 || binary.BigEndian.Uint32(r.Data) != uint32(len(r.Data)-4) || binary.BigEndian.Uint16(r.Data[6:8]) != 0x10 {
		t.Fatalf("configuration header: %x", r.Data)
	}
	var previous uint16
	for at := 8; at < len(r.Data); {
		f := r.Data[at : at+4+int(r.Data[at+3])]
		code := binary.BigEndian.Uint16(f)
		if at > 8 && code <= previous {
			t.Fatal("unordered features")
		}
		previous = code
		if code >= 0x20 {
			t.Fatal("unimplemented writable feature advertised")
		}
		at += len(f)
	}
	r = query(2, 0x10, 2048)
	if len(r.Data) != 20 || binary.BigEndian.Uint16(r.Data[8:]) != 0x10 || binary.BigEndian.Uint32(r.Data[12:]) != 2048 || binary.BigEndian.Uint16(r.Data[16:]) != 1 {
		t.Fatal("random-readable geometry")
	}
	if r = query(2, 0x20, 2048); len(r.Data) != 8 {
		t.Fatal("unknown feature did not return header only")
	}
	if r = query(0, 0, 4); len(r.Data) != 4 || binary.BigEndian.Uint32(r.Data) <= 4 {
		t.Fatal("allocation limit destroyed complete length")
	}
	if r = query(0, 0, 0); len(r.Data) != 0 || r.Status != 0 {
		t.Fatal("zero allocation")
	}
	if _, err = d.Execute([]byte{0x1b, 0, 0, 0, 2, 0}); err != nil {
		t.Fatal(err)
	}
	r = query(1, 0, 2048)
	if r.Status != 0 || binary.BigEndian.Uint16(r.Data[6:8]) != 0 {
		t.Fatal("ejected profile remains current")
	}
	for at := 8; at < len(r.Data); at += 4 + int(r.Data[at+3]) {
		if binary.BigEndian.Uint16(r.Data[at:]) >= 0x10 {
			t.Fatal("ejected medium features remain current")
		}
	}
	if query(3, 0, 2048).Status != 2 {
		t.Fatal("reserved request type accepted")
	}
}
