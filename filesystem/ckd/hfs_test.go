package ckd

import (
	"io"
	"testing"
)

func hfsFixture() *HFS {
	b := make([]byte, 8192)
	copy(b[4096:], []byte("payload-and-allocation-slack"))
	h := &HFS{igw: &IGW{source: raw(b)}, attrs: map[[20]byte][]byte{}, limit: 10}
	inode := func(obj [6]byte, kind byte, size uint64) {
		v := make([]byte, 216)
		copy(v, eb("IGWPFAR", 8))
		be.PutUint32(v[8:], 216)
		v[12] = 1
		be.PutUint64(v[20:], size)
		copy(v[60:], eb("IFSP", 4))
		v[64] = 1
		v[124] = kind
		h.attrs[igwKey(3, obj, 0x9001)] = v
	}
	f, l := [6]byte{0, 0, 0, 8, 0, 0}, [6]byte{0, 0, 0, 9, 0, 0}
	inode(hfsRoot, 1, 0)
	inode(f, 3, 7)
	inode(l, 5, 4)
	h.attrs[igwKey(3, f, 0x7003)] = testRun(1, 1)
	h.attrs[igwKey(3, l, 0x9005)] = []byte{1, 0, 0, 0, 0, 4, 0x4b, 0x4b, 0x61, 0xc1}
	b[0], b[1], b[11], b[12], b[25], b[30] = 52, 1, 0xd5, 0xc4, 255, 1
	pos := 312
	for _, e := range []struct {
		name string
		obj  [6]byte
	}{{".", hfsRoot}, {"..", hfsRoot}, {"A", f}, {"ALIAS", f}, {"LINK", l}, {"LOOP", hfsRoot}} {
		n := len(e.name)
		length := 5 + n + 20
		be.PutUint16(b[pos:], uint16(length))
		b[pos+2] = 0xc0
		b[pos+4] = byte(255 - n)
		copy(b[pos+5:], eb(e.name, n))
		value := b[pos+5+n : pos+length]
		copy(value[6:12], e.obj[:])
		be.PutUint16(value[14:], uint16(n))
		pos += length
	}
	be.PutUint16(b[307:], uint16(pos-307))
	be.PutUint16(b[309:], uint16(pos-307))
	b[311] = 6
	be.PutUint16(b[48:], uint16(4094-pos))
	be.PutUint16(b[50:], 4094)
	be.PutUint16(b[4094:], 0xa55a)
	d := make([]byte, 64)
	d[0] = 1
	copy(d[1:20], b[2:21])
	h.attrs[igwKey(3, hfsRoot, 0x4002)] = d
	h.attrs[igwKey(3, hfsRoot, 0x7003)] = testRun(0, 1)
	return h
}
func TestHFSLogicalFilesLinksAndCycles(t *testing.T) {
	h := hfsFixture()
	es, err := h.View().Entries()
	if err != nil || len(es) != 4 {
		t.Fatal(es, err)
	}
	for _, e := range es {
		switch e.Name {
		case "A", "ALIAS":
			data := make([]byte, 10)
			n, err := e.Reader.ReadAt(data, 0)
			if e.Reader.Size() != 7 || n != 7 || err != io.EOF || string(data[:7]) != "payload" {
				t.Fatal(n, err, data)
			}
		case "LINK":
			if e.Reader != nil || e.Kind != "symlink" || e.Attributes["link"] != "../A" {
				t.Fatal(e)
			}
		case "LOOP":
			if _, err := e.View.Entries(); err == nil {
				t.Fatal("cycle accepted")
			}
		}
	}
	h.limit = 1
	if _, err := h.Directory(hfsRoot); err == nil {
		t.Fatal("limit ignored")
	}
}
func TestHFSMalformedAndEmptyInode(t *testing.T) {
	f := [6]byte{0, 0, 0, 8, 0, 0}
	h := hfsFixture()
	v := h.attr(f, 0x9001)
	be.PutUint64(v[20:], 8193)
	if _, err := h.File(f); err == nil {
		t.Fatal("short allocation accepted")
	}
	be.PutUint64(v[20:], 0)
	delete(h.attrs, igwKey(3, f, 0x7003))
	data, err := h.File(f)
	if err != nil || data.Size() != 0 {
		t.Fatal(data, err)
	}
	v[124] = 255
	if _, err := h.Inode(f); err == nil {
		t.Fatal("unknown inode accepted")
	}
	h = hfsFixture()
	link := [6]byte{0, 0, 0, 9, 0, 0}
	h.attr(link, 0x9005)[5] = 5
	if _, err := h.Link(link); err == nil {
		t.Fatal("bad link length accepted")
	}
	h = hfsFixture()
	h.attr(hfsRoot, 0x4002)[35] = 2
	if _, err := h.Directory(hfsRoot); err == nil {
		t.Fatal("bad root accepted")
	}
	if got := HFSDisplayName([]byte{0xc1, 0x40, 0x6c, 0x00}); got != "A %6C%00" {
		t.Fatal(got)
	}
}
