package ibmiimd

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func copyFixture() []byte {
	b := make([]byte, copyHeaderBytes+8192)
	be := binary.BigEndian
	b[192+128+8] = 0xf0 // Observed unmapped control record; opaque fields are preserved.
	copy(b, copyMagic)
	be.PutUint32(b[24:], 0x40000003)
	be.PutUint32(b[28:], 8192)
	for i, address := range []uint64{0x90010000, 0x200000} {
		r := b[192+i*64 : 192+(i+1)*64]
		be.PutUint64(r[16:], address)
		be.PutUint32(r[24:], 8192)
		be.PutUint32(r[28:], 0x98000000)
		be.PutUint64(r[40:], uint64(i*4096))
		be.PutUint32(r[48:], 4096)
	}
	d := b[copyHeaderBytes:]
	be.PutUint32(d, 0x80000002)
	copy(d[4:], directoryMagic)
	for i, address := range []uint64{0x201200, 0x200000} {
		r := d[32+i*32 : 64+i*32]
		be.PutUint32(r, uint32(i+1))
		be.PutUint32(r[4:], 0xffffffff)
		be.PutUint32(r[8:], 1)
		be.PutUint64(r[16:], address)
	}
	copy(d[96:], endMagic)
	copy(b[copyHeaderBytes+4096+512:], bytes.Repeat([]byte{0xa5}, 512))
	return b
}
func TestCopyDirectoryAddressedViews(t *testing.T) {
	source := &starfile.Bytes{Data: copyFixture()}
	c, err := OpenCopyDirectory(source, 3, 2, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Segments) != 2 || c.ReservedRecords != 1 || len(c.LIDs) != 2 || c.LIDs[0].Data == nil || c.LIDs[1].Data != nil || c.LIDs[1].UnavailableReason == "" {
		t.Fatal(c)
	}
	data, err := starfile.ReadAll(c.LIDs[0].Data)
	if err != nil || !bytes.Equal(data, bytes.Repeat([]byte{0xa5}, 512)) {
		t.Fatal(data, err)
	}
	for _, address := range []uint64{0x200000, 0x200fff, 0x202000, 0xfffffffffffffff0} {
		if _, err := c.SavedAt(address, 32); err == nil {
			t.Fatal("hole/invalid range accepted", address)
		}
	}
	if _, err := c.SavedAt(0x201ff0, 32); err == nil {
		t.Fatal("read crossed saved segment")
	}
	c.Segments[1].CopiedAddress = 0
	if _, err := c.SavedAt(0x201200, 512); err != nil {
		t.Fatal("mutable metadata changed validated map", err)
	}
	found, err := auto.Identify(source, auto.Options{})
	if err != nil || found.Format != "ibmi_copydir" {
		t.Fatal(found, err)
	}
}
func TestCopyDirectoryMalformed(t *testing.T) {
	be := binary.BigEndian
	for name, mutate := range map[string]func([]byte){
		"huge records":     func(b []byte) { be.PutUint32(b[24:], 0x40ffffff) },
		"body":             func(b []byte) { be.PutUint32(b[28:], 8191) },
		"overlap":          func(b []byte) { be.PutUint64(b[192+64+16:], 0x90011000) },
		"offset":           func(b []byte) { be.PutUint64(b[192+64+40:], 0) },
		"omission":         func(b []byte) { be.PutUint32(b[192+48:], 4095) },
		"address overflow": func(b []byte) { be.PutUint64(b[192+16:], 0xfffffffffffff000) },
		"reserved":         func(b []byte) { be.PutUint32(b[192+128+24:], 1) },
		"directory count":  func(b []byte) { be.PutUint32(b[copyHeaderBytes:], 0x80000100) },
		"duplicate":        func(b []byte) { be.PutUint32(b[copyHeaderBytes+64:], 1) },
		"directory marker": func(b []byte) { b[copyHeaderBytes+96] = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			b := copyFixture()
			mutate(b)
			if _, err := OpenCopyDirectory(&starfile.Bytes{Data: b}, 256, 1000, 0); err == nil {
				t.Fatal("malformed copydir accepted")
			}
		})
	}
	src := &starfile.Bytes{Data: copyFixture()}
	for _, limit := range []struct {
		segments, lids int
		bytes          int64
	}{{2, 2, 0}, {3, 1, 0}, {3, 2, 8191}} {
		if _, err := OpenCopyDirectory(src, limit.segments, limit.lids, limit.bytes); err == nil {
			t.Fatal("budget ignored", limit)
		}
	}
}
func FuzzCopyDirectory(f *testing.F) {
	f.Add(copyFixture())
	f.Add([]byte("COPYDIR"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		c, err := OpenCopyDirectory(&starfile.Bytes{Data: b}, 128, 128, 1<<20)
		if err == nil {
			for _, s := range c.Segments {
				if s.Offset < copyHeaderBytes || int64(s.StoredBytes) > int64(len(b))-s.Offset {
					t.Fatal("invalid borrowed extent")
				}
			}
		}
	})
}
