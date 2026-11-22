package scsi

import (
	"encoding/binary"
	"testing"
)

func TestOpticalTOCSessionGeometryAndAllocation(t *testing.T) {
	d, err := NewOptical(make(disc, 321*2048))
	if err != nil {
		t.Fatal(err)
	}
	c := []byte{0x43, 0, 1, 0, 0, 0, 0, 0, 12, 0}
	run := func() Result {
		t.Helper()
		r, e := d.Execute(c)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	r := run()
	if r.Status != 0 || len(r.Data) != 12 || binary.BigEndian.Uint16(r.Data) != 10 || r.Data[2] != 1 || r.Data[3] != 1 || r.Data[5] != 0x14 || r.Data[6] != 1 || binary.BigEndian.Uint32(r.Data[8:]) != 0 {
		t.Fatalf("native multi-session response: %x", r.Data)
	}
	c[2], c[8] = 0, 255
	r = run()
	if len(r.Data) != 20 || r.Data[14] != 0xaa || binary.BigEndian.Uint32(r.Data[16:]) != 321 {
		t.Fatal("lead-out does not match actual geometry")
	}
	c[6] = 0xaa
	if r = run(); len(r.Data) != 12 || r.Data[6] != 0xaa {
		t.Fatal("start-track selection")
	}
	c[1] = 2
	r = run()
	if r.Data[8] != 0 || r.Data[9] != 0 || r.Data[10] != 6 || r.Data[11] != 21 {
		t.Fatalf("lead-out MSF: %x", r.Data[8:])
	}
	c[8] = 2
	if r = run(); len(r.Data) != 2 || binary.BigEndian.Uint16(r.Data) != 10 {
		t.Fatal("short allocation corrupts complete length")
	}
	c[6] = 2
	if run().Status != 2 {
		t.Fatal("absent track accepted")
	}
	c[2] = 3
	if run().Status != 2 {
		t.Fatal("DVD-ROM exposes nonexistent PMA")
	}
}
