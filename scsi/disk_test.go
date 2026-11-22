package scsi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/tinyrange/trex/block"
	blockstar "github.com/tinyrange/trex/block/star"
)

type verifyDiskMedia struct {
	block.Device
	corrupt, failRead bool
	reads, writes     int
}

func (d *verifyDiskMedia) ReadAt(p []byte, off int64) (int, error) {
	d.reads++
	if d.failRead {
		return 0, errors.New("unreadable medium")
	}
	return d.Device.ReadAt(p, off)
}

func (d *verifyDiskMedia) WriteAt(p []byte, off int64) (int, error) {
	d.writes++
	if d.corrupt {
		p = bytes.Clone(p)
		p[0] ^= 1
	}
	return d.Device.(block.Writer).WriteAt(p, off)
}

func TestDiskWriteAndVerifyReadsActualStorage(t *testing.T) {
	base, _ := block.NewZeroDevice(2<<20, 512)
	overlay, _ := blockstar.NewOverlayDevice(base, 2<<20, 4096)
	media := &verifyDiskMedia{Device: overlay}
	d, _ := NewDisk(media, DiskIdentity{})
	cdb := make([]byte, 10)
	cdb[0] = 0x2e
	binary.BigEndian.PutUint32(cdb[2:], 9)
	binary.BigEndian.PutUint16(cdb[7:], 256)
	want := bytes.Repeat([]byte{0x5a}, 256*512)
	p, err := d.Prepare(0, cdb, want)
	if err != nil || p.Result().Status != 0 || media.writes != 0 || media.reads != 0 {
		t.Fatal("verification must follow committed writes", err)
	}
	if err = p.Complete(); err != nil || media.writes != 1 || media.reads != 2 {
		t.Fatal("missing bounded readback", err, media.writes, media.reads)
	}
	got := make([]byte, len(want))
	overlay.ReadAt(got, 9*512)
	if !bytes.Equal(got, want) {
		t.Fatal("write and verify bytes not stored")
	}
	cdb[1] = 2 // BYTCHK=1 compares backing bytes, not the input buffer.
	media.corrupt = true
	if _, err = d.Execute(cdb, want); err == nil {
		t.Fatal("corrupt write was reported verified")
	}
	media.corrupt, media.failRead = false, true
	cdb[1] = 0 // Medium verification must also really read.
	if _, err = d.Execute(cdb, want); err == nil {
		t.Fatal("unreadable written medium was reported verified")
	}
	media.failRead = false
	for _, flags := range []byte{4, 6, 8, 0x20} {
		before := media.writes
		cdb[1] = flags
		r, err := d.Execute(cdb, want)
		if err != nil || r.Status != 2 || r.Sense[12] != 0x24 || media.writes != before {
			t.Fatal("unsupported verify flags changed storage", flags, err)
		}
	}
}

func TestDiskPreparedWritesBoundsAndSense(t *testing.T) {
	base, _ := block.NewZeroDevice(64<<30, 512)
	media, err := blockstar.NewOverlayDevice(base, 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDisk(media, DiskIdentity{"TEST", "Direct Disk", "1234", "serial"})
	if err != nil {
		t.Fatal(err)
	}
	cdb := make([]byte, 16)
	cdb[0] = 0x2a
	binary.BigEndian.PutUint32(cdb[2:], uint32((64<<30)/512-1))
	binary.BigEndian.PutUint16(cdb[7:], 1)
	want := bytes.Repeat([]byte{0x5a}, 512)
	p, err := d.Prepare(0, cdb, want)
	if err != nil || p.Result().Status != 0 {
		t.Fatalf("prepare: %v %+v", err, p)
	}
	got := make([]byte, 512)
	media.ReadAt(got, (64<<30)-512)
	if !bytes.Equal(got, make([]byte, 512)) {
		t.Fatal("prepare wrote before completion")
	}
	want[0] = 9
	if err := p.Complete(); err != nil {
		t.Fatal(err)
	}
	if p.Complete() == nil {
		t.Fatal("completed twice")
	}
	cdb[0] = 0x28
	r, err := d.Execute(cdb, nil)
	if err != nil || len(r.Data) != 512 || r.Data[0] != 0x5a {
		t.Fatalf("backed read: %v %+v", err, r)
	}
	cdb[0] = 0x2a
	binary.BigEndian.PutUint16(cdb[7:], 2)
	r, err = d.Execute(cdb, bytes.Repeat([]byte{7}, 1024))
	if err != nil || r.Status != 2 || r.Sense[12] != 0x21 {
		t.Fatal("write beyond end accepted")
	}
	media.ReadAt(got, (64<<30)-512)
	if got[0] != 0x5a {
		t.Fatal("invalid write changed disk")
	}
	r, err = d.Execute([]byte{3, 0, 0, 0, 18, 0}, nil)
	if err != nil || r.Data[12] != 0x21 {
		t.Fatal("request sense lost failure")
	}
	r, _ = d.Execute([]byte{3, 0, 0, 0, 18, 0}, nil)
	if r.Data[12] != 0 {
		t.Fatal("request sense did not consume sense")
	}
	cdb[0] = 0x2a
	binary.BigEndian.PutUint16(cdb[7:], 1)
	r, err = d.Execute(cdb, []byte{1})
	if err != nil || r.Status != 2 || r.Sense[12] != 0x1a {
		t.Fatal("short data-out accepted")
	}
	readonly, _ := NewDisk(base, DiskIdentity{})
	r, err = readonly.Execute(cdb, make([]byte, 512))
	if err != nil || r.Status != 2 || r.Sense[2] != 7 {
		t.Fatal("read-only target accepted write")
	}
}

func TestDiskCapacityIdentityAndReservations(t *testing.T) {
	base, _ := block.NewZeroDevice(64<<30, 512)
	d, _ := NewDisk(base, DiskIdentity{"TEST", "Direct Disk", "0001", "abc"})
	r, err := d.Execute([]byte{0x12, 0, 0, 0, 96, 0}, nil)
	if err != nil || r.Data[0] != 0 || string(r.Data[8:16]) != "TEST    " || string(r.Data[16:32]) != "Direct Disk     " {
		t.Fatal("direct-access identity")
	}
	for _, page := range []byte{0xfa, 0xb1, 0xff} {
		r, err = d.Execute([]byte{0x12, 1, page, 0, 255, 0}, nil)
		if err != nil || r.Status != 2 || len(r.Data) != 0 || r.Sense[2] != 5 || r.Sense[12] != 0x24 {
			t.Fatalf("unadvertised VPD%02x: %+v %v", page, r, err)
		}
	}
	r, err = d.Execute([]byte{0x12, 1, 0x83, 0, 255, 0}, nil)
	if err != nil || string(r.Data[8:16]) != "TEST    " || int(r.Data[7]) != len(r.Data)-8 {
		t.Fatal("T10 identifier framing")
	}
	r, _ = d.Execute([]byte{0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0}, nil)
	if binary.BigEndian.Uint32(r.Data) != (64<<30)/512-1 || binary.BigEndian.Uint32(r.Data[4:]) != 512 {
		t.Fatal("real capacity")
	}
	cmd := make([]byte, 16)
	cmd[0], cmd[1] = 0x9e, 0x10
	binary.BigEndian.PutUint32(cmd[10:], 32)
	r, err = d.Execute(cmd, nil)
	if err != nil || binary.BigEndian.Uint64(r.Data) != (64<<30)/512-1 {
		t.Fatal("capacity16")
	}
	cmd = make([]byte, 10)
	cmd[0] = 0x56
	p, _ := d.Prepare(7, cmd, nil)
	p.Complete()
	p, _ = d.Prepare(8, make([]byte, 6), nil)
	if p.Result().Status != 0x18 {
		t.Fatal("reservation owner not enforced")
	}
	cmd[0] = 0x57
	p, _ = d.Prepare(8, cmd, nil)
	p.Complete()
	if !d.reserved {
		t.Fatal("non-owner released disk")
	}
	p, _ = d.Prepare(7, cmd, nil)
	p.Complete()
	if d.reserved {
		t.Fatal("owner release failed")
	}
	if _, err := NewDisk(base, DiskIdentity{Vendor: "toolongvendor"}); err == nil {
		t.Fatal("identity silently truncated")
	}
}

func TestDiskWriteSameBackedPatternAndZero(t *testing.T) {
	base, _ := block.NewZeroDevice(2<<20, 512)
	media, _ := blockstar.NewOverlayDevice(base, 2<<20, 4096)
	d, _ := NewDisk(media, DiskIdentity{})
	cdb := make([]byte, 16)
	cdb[0] = 0x93
	binary.BigEndian.PutUint64(cdb[2:], 3)
	binary.BigEndian.PutUint32(cdb[10:], 2048)
	pattern := make([]byte, 512)
	for i := range pattern {
		pattern[i] = byte(i * 7)
	}
	p, err := d.Prepare(0, cdb, pattern)
	if err != nil || p.Result().Status != 0 {
		t.Fatal("prepare repeat", err)
	}
	got := make([]byte, 512)
	media.ReadAt(got, 3*512)
	if !bytes.Equal(got, make([]byte, 512)) {
		t.Fatal("prepared repeat changed disk")
	}
	if err = p.Complete(); err != nil {
		t.Fatal(err)
	}
	for _, lba := range []int64{3, 130, 2050} {
		media.ReadAt(got, lba*512)
		if !bytes.Equal(got, pattern) {
			t.Fatal("repeated pattern missing", lba)
		}
	}
	media.ReadAt(got, 2051*512)
	if !bytes.Equal(got, make([]byte, 512)) {
		t.Fatal("write same exceeded range")
	}
	r, err := d.Execute(cdb, make([]byte, 512))
	if err != nil || r.Status != 0 {
		t.Fatal("zero repeat", err)
	}
	media.ReadAt(got, 2050*512)
	if !bytes.Equal(got, make([]byte, 512)) {
		t.Fatal("zero repeat did not clear bytes")
	}
	// NDOB supplies the genuine zero initialization pattern without data-out.
	cdb[1] = 1
	binary.BigEndian.PutUint64(cdb[2:], 4095)
	binary.BigEndian.PutUint32(cdb[10:], 0)
	r, err = d.Execute(cdb, nil)
	if err != nil || r.Status != 0 {
		t.Fatal("zero-count NDOB through last LBA", err)
	}
	binary.BigEndian.PutUint32(cdb[10:], 2)
	r, err = d.Execute(cdb, nil)
	if err != nil || r.Status != 2 || r.Sense[12] != 0x21 {
		t.Fatal("bad repeat range accepted")
	}
	cdb[1] = 8
	binary.BigEndian.PutUint32(cdb[10:], 1)
	r, err = d.Execute(cdb, pattern)
	if err != nil || r.Status != 2 || r.Sense[12] != 0x24 {
		t.Fatal("unsupported thin provisioning claimed")
	}
}
