package mozilla

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/binary/pe"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"testing"
)

func resourcePE(t *testing.T) []byte {
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write([]byte("hello resource"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint32(payload, uint32(z.Len()))
	binary.LittleEndian.PutUint32(payload[4:], 14)
	payload = append(payload, z.Bytes()...)
	b := make([]byte, 1024)
	copy(b, "MZ")
	put := binary.LittleEndian.PutUint32
	put16 := binary.LittleEndian.PutUint16
	put(b[60:], 128)
	copy(b[128:], "PE\x00\x00")
	put16(b[132:], 0x14c)
	put16(b[134:], 1)
	put16(b[148:], 224)
	put16(b[152:], 0x10b)
	put(b[152+92:], 16)
	put(b[152+112:], 0x1000)
	put(b[152+116:], 512)
	sec := b[376:]
	copy(sec, ".rsrc")
	put(sec[8:], 512)
	put(sec[12:], 0x1000)
	put(sec[16:], 512)
	put(sec[20:], 512)
	r := b[512:]
	put16(r[12:], 1)
	put(r[16:], 0x80000000|128)
	put(r[20:], 0x80000000|24)
	put16(r[24+12:], 1)
	put(r[40:], 0x80000000|144)
	put(r[44:], 0x80000000|48)
	put16(r[48+14:], 1)
	put(r[64:], 1033)
	put(r[68:], 80)
	put(r[80:], 0x1000+256)
	put(r[84:], uint32(len(payload)))
	for off, name := range map[int]string{128: "FILE", 144: "HELLO.TXT"} {
		put16(r[off:], uint16(len(name)))
		for i, c := range name {
			put16(r[off+2+i*2:], uint16(c))
		}
	}
	copy(r[256:], payload)
	return b
}
func TestResourcesAndFraming(t *testing.T) {
	b := resourcePE(t)
	r := &starfile.Bytes{Data: b}
	resources, err := pe.Resources(r, 100)
	if err != nil || len(resources) != 1 || resources[0].Path != "FILE/HELLO.TXT/#1033" {
		t.Fatalf("%+v %v", resources, err)
	}
	view, err := Open(b, r, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	es, err := view.Entries()
	if err != nil || len(es) != 1 {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(es[0].Reader, 0, es[0].Reader.Size()))
	if err != nil || string(got) != "hello resource" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err = Open(b, r, auto.Options{MaxExpandedBytes: 3}); !errors.Is(err, auto.ErrLimit) {
		t.Fatalf("limit: %v", err)
	}
	for _, at := range []int{512 + 256, 512 + 256 + 4, 512 + 256 + 8} {
		bad := bytes.Clone(b)
		bad[at] ^= 0x80
		if _, err := Open(bad, &starfile.Bytes{Data: bad}, auto.Options{}); err == nil {
			t.Fatal("accepted malformed resource")
		}
	}
	for _, at := range []int{512 + 20, 512 + 68, 512 + 80} {
		bad := bytes.Clone(b)
		binary.LittleEndian.PutUint32(bad[at:], 0xffffffff)
		if _, err := pe.Resources(&starfile.Bytes{Data: bad}, 100); err == nil {
			t.Fatal("accepted invalid resource tree")
		}
	}
}
