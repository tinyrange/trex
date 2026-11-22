package scsi

import (
	"encoding/binary"
	"testing"
)

func TestOpticalDiscInformationFinalizedDVD(t *testing.T) {
	d, err := NewOptical(make(disc, 7*2048))
	if err != nil {
		t.Fatal(err)
	}
	c := []byte{0x51, 0, 0, 0, 0, 0, 0, 0, 48, 0}
	r, err := d.Execute(c)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != 0 || len(r.Data) != 34 || binary.BigEndian.Uint16(r.Data) != 32 || r.Data[2] != 0x0e || r.Data[3] != 1 || r.Data[4] != 1 || r.Data[5] != 1 || r.Data[6] != 1 || r.Data[7] != 0x20 {
		t.Fatalf("disc status/session: %x", r.Data)
	}
	for _, b := range r.Data[8:] {
		if b != 0 {
			t.Fatal("read-only DVD advertised writable/recording metadata")
		}
	}
	c[8] = 2
	r, _ = d.Execute(c)
	if len(r.Data) != 2 || binary.BigEndian.Uint16(r.Data) != 32 {
		t.Fatal("short allocation changed complete length")
	}
	c[1] = 1
	if r, _ = d.Execute(c); r.Status != 2 {
		t.Fatal("unsupported information type accepted")
	}
	d.Execute([]byte{0x1b, 0, 0, 0, 2, 0})
	c[1] = 0
	if r, _ = d.Execute(c); r.Status != 2 || r.Sense[12] != 0x3a {
		t.Fatal("disc information ignored ejected state")
	}
}
