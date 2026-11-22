package scsi

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/block"
	"io"
	"testing"
)

type disc []byte

func TestBootWithEmptyOpticalDrive(t *testing.T) {
	d, err := NewOptical(nil)
	if err != nil {
		t.Fatal(err)
	}
	inquiry, err := d.Execute([]byte{0x12, 0, 0, 0, 36, 0})
	if err != nil || len(inquiry.Data) != 36 || inquiry.Data[0] != 5 {
		t.Fatalf("empty drive inquiry: %+v, %v", inquiry, err)
	}
	for _, cdb := range [][]byte{{0, 0, 0, 0, 0, 0}, {0x1b, 0, 0, 0, 3, 0}, {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0}} {
		r, err := d.Execute(cdb)
		if err != nil || r.Status != 2 || r.Sense[2] != 2 || r.Sense[12] != 0x3a {
			t.Fatalf("empty medium command %x: %+v, %v", cdb, r, err)
		}
	}
	config, err := d.Execute([]byte{0x46, 0, 0, 0, 0, 0, 0, 0, 8, 0})
	if err != nil || len(config.Data) != 8 || binary.BigEndian.Uint16(config.Data[6:]) != 0 {
		t.Fatalf("empty medium current profile: %+v, %v", config, err)
	}
	if err := d.ChangeMedia(make(disc, 2048)); err != nil {
		t.Fatal(err)
	}
	for _, status := range []byte{2, 0} {
		r, err := d.Execute(make([]byte, 6))
		if err != nil || r.Status != status || status == 2 && r.Sense[12] != 0x28 {
			t.Fatalf("disc insertion: %+v, %v", r, err)
		}
	}
}

func (d disc) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(d)) {
		return 0, io.EOF
	}
	n := copy(p, d[off:])
	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (d disc) Geometry() block.Geometry {
	return block.Geometry{Size: int64(len(d)), LogicalBlockSize: 2048}
}
func (d disc) Capabilities() block.Capabilities { return block.Capabilities{} }

func TestOpticalMediaReplacementLocksAttentionAndSnapshot(t *testing.T) {
	first := disc(bytes.Repeat([]byte{0x51}, 2048))
	second := disc(bytes.Repeat([]byte{0x92}, 4096))
	d, _ := NewOptical(first)
	command := func(owner uint64, cdb []byte) Result {
		t.Helper()
		r, err := d.ExecuteFrom(owner, cdb)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	ready := make([]byte, 6)
	for _, owner := range []uint64{7, 8} {
		command(owner, ready)
	}
	read := []byte{0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0}
	for _, lock := range []byte{1, 3} {
		command(7, []byte{0x1e, 0, 0, 0, lock, 0})
		if d.ChangeMedia(second) == nil || d.mediaGeneration != 0 {
			t.Fatal("locked replacement changed media")
		}
		if r := command(7, read); !bytes.Equal(r.Data, first) {
			t.Fatal("rejected replacement changed bytes")
		}
		command(7, []byte{0x1e, 0, 0, 0, lock &^ 1, 0})
	}
	if d.ChangeMedia(make(disc, 2049)) == nil || d.ChangeMedia(nil) == nil {
		t.Fatal("invalid replacement accepted")
	}
	command(7, []byte{0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err := d.ChangeMedia(second); err != nil || !d.reserved || d.reservationOwner != 7 {
		t.Fatal("replacement reset reservation", err)
	}
	saved := d
	command(7, []byte{0x12, 0, 0, 0, 36, 0})
	command(7, []byte{3, 0, 0, 0, 18, 0})
	if r := command(7, ready); r.Status != 2 || r.Sense[2] != 6 || r.Sense[12] != 0x28 {
		t.Fatal("inquiry/sense consumed pending medium-change attention")
	}
	if r := command(7, []byte{3, 0, 0, 0, 18, 0}); r.Data[2] != 6 || r.Data[12] != 0x28 {
		t.Fatal("medium-change sense was not retained")
	}
	if r := command(7, ready); r.Status != 0 {
		t.Fatal("unit attention not acknowledged")
	}
	if r, err := saved.ExecuteFrom(7, ready); err != nil || r.Status != 2 || r.Sense[12] != 0x28 {
		t.Fatal("acknowledgement mutated copied target", err)
	}
	command(7, []byte{0x57, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if r := command(8, ready); r.Status != 2 || r.Sense[12] != 0x28 {
		t.Fatal("one initiator acknowledged another's attention")
	}
	read[5] = 1
	if r := command(7, read); !bytes.Equal(r.Data, second[2048:]) {
		t.Fatal("replacement did not change backed bytes/geometry")
	}
	// Persistent Prevent still permits an explicit initiator eject. Once the
	// tray is open, the operator can replace the medium and close it.
	command(7, []byte{0x1e, 0, 0, 0, 3, 0})
	if r := command(7, []byte{0x1b, 0, 0, 0, 2, 0}); r.Status != 0 || !d.ejected {
		t.Fatal("persistent lock blocked initiator eject")
	}
	if err := d.ChangeMedia(first); err != nil || d.ejected || d.stopped || !d.persistentPrevent {
		t.Fatal("open-tray replacement reset drive state", err)
	}
}

func TestOpticalReservations(t *testing.T) {
	d, err := NewOptical(make(disc, 2048))
	if err != nil {
		t.Fatal(err)
	}
	command := func(owner uint64, op byte) Result {
		t.Helper()
		cdb := make([]byte, 10)
		cdb[0] = op
		r, err := d.ExecuteFrom(owner, cdb)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if command(11, 0x56).Status != 0 || command(11, 0x56).Status != 0 {
		t.Fatal("owner cannot reserve repeatedly")
	}
	saved := d
	for _, op := range []byte{0x00, 0x56, 0x28} {
		if r := command(22, op); r.Status != 0x18 || len(r.Sense) != 0 || len(r.Data) != 0 {
			t.Fatalf("non-owner command%02x: %+v", op, r)
		}
	}
	for _, op := range []byte{0x12, 0x03, 0x57} {
		if command(22, op).Status != 0 {
			t.Fatalf("reservation blocks exempt command%02x", op)
		}
	}
	if command(22, 0x00).Status != 0x18 {
		t.Fatal("non-owner released reservation")
	}
	if command(11, 0x57).Status != 0 || command(22, 0x00).Status != 0 {
		t.Fatal("owner release did not restore access")
	}
	d = saved
	if command(22, 0x00).Status != 0x18 {
		t.Fatal("copied reservation state was lost")
	}
	bad := make([]byte, 10)
	bad[0], bad[1] = 0x57, 0x10
	if r, err := d.ExecuteFrom(11, bad); err != nil || r.Status != 2 || r.Sense[12] != 0x24 {
		t.Fatal("unsupported third-party release accepted")
	}
	if command(22, 0x00).Status != 0x18 {
		t.Fatal("invalid release modified reservation")
	}
}

func TestOpticalNativeReadSenseAndMediaState(t *testing.T) {
	media := make(disc, 3*2048)
	for i := range media {
		media[i] = byte(i*7 + i/2048)
	}
	d, err := NewOptical(media)
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
	r := run([]byte{0x12, 0, 0, 0, 96, 0})
	if r.Status != 0 || len(r.Data) != 36 || r.Data[0] != 5 || r.Data[1] != 0x80 || string(r.Data[8:16]) != "TINYRNGX" {
		t.Fatal("inquiry does not describe assigned optical device")
	}
	r = run([]byte{0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if binary.BigEndian.Uint32(r.Data) != 2 || binary.BigEndian.Uint32(r.Data[4:]) != 2048 {
		t.Fatal("capacity does not match media")
	}
	for _, op := range []byte{0x28, 0xa8, 0x88} {
		c := make([]byte, 16)
		c[0] = op
		if op == 0x88 {
			binary.BigEndian.PutUint64(c[2:10], 1)
			binary.BigEndian.PutUint32(c[10:14], 2)
		} else {
			binary.BigEndian.PutUint32(c[2:6], 1)
			if op == 0x28 {
				binary.BigEndian.PutUint16(c[7:9], 2)
			} else {
				binary.BigEndian.PutUint32(c[6:10], 2)
			}
		}
		r = run(c)
		if r.Status != 0 || !bytes.Equal(r.Data, media[2048:]) {
			t.Fatalf("READ%02x bytes do not match backing", op)
		}
	}
	r = run([]byte{0x28, 0, 0, 0, 0, 2, 0, 0, 2, 0})
	if r.Status != 2 || r.Sense[2] != 5 || r.Sense[12] != 0x21 {
		t.Fatal("out-of-range read")
	}
	saved := d
	r = run([]byte{3, 0, 0, 0, 18, 0})
	if r.Data[12] != 0x21 {
		t.Fatal("request sense lost last failure")
	}
	r = run([]byte{3, 0, 0, 0, 18, 0})
	if r.Data[2] != 0 {
		t.Fatal("request sense did not clear")
	}
	d = saved
	r = run([]byte{3, 0, 0, 0, 18, 0})
	if r.Data[12] != 0x21 {
		t.Fatal("copied device state aliased sense")
	}
	r = run([]byte{0x2a, 0, 0, 0, 0, 0, 0, 0, 1, 0})
	if r.Status != 2 || r.Sense[2] != 7 || r.Sense[12] != 0x27 {
		t.Fatal("read-only medium accepted write")
	}
	run([]byte{0x1e, 0, 0, 0, 1, 0})
	run([]byte{0x1e, 0, 0, 0, 2, 0})
	if !d.prevent || d.persistentPrevent {
		t.Fatal("persistent allow changed ordinary lock")
	}
	r = run([]byte{0x1b, 0, 0, 0, 2, 0})
	if r.Status != 2 {
		t.Fatal("prevent-removal ignored")
	}
	run([]byte{0x1e, 0, 0, 0, 0, 0})
	run([]byte{0x1e, 0, 0, 0, 3, 0})
	if d.prevent || !d.persistentPrevent {
		t.Fatal("persistent lock changed ordinary lock")
	}
	run([]byte{0x1b, 0, 0, 0, 2, 0})
	r = run([]byte{0, 0, 0, 0, 0, 0})
	if r.Sense[12] != 0x3a {
		t.Fatal("eject did not change medium state")
	}
	run([]byte{0x1b, 0, 0, 0, 3, 0})
	if run([]byte{0, 0, 0, 0, 0, 0}).Status != 0 {
		t.Fatal("load did not restore medium")
	}
	if _, err = d.Execute([]byte{0xff, 0, 0, 0, 0, 0}); err == nil {
		t.Fatal("unknown feature silently completed")
	}
}
