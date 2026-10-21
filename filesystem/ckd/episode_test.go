package ckd

import (
	"bytes"
	"io"
	"math"
	"testing"
)

func episodeFixture() []byte {
	b := make([]byte, 16*8192)
	sb := b[8*8192:]
	be.PutUint32(sb[4:], 0x3198a2e0)
	be.PutUint32(sb[8:], 1)
	be.PutUint32(sb[12:], 0x8946f098)
	be.PutUint32(sb[20:], 8192)
	be.PutUint32(sb[24:], 1024)
	be.PutUint32(sb[32:], 15)
	anode := func(block, index, slot int, flags uint32, size uint64) []byte {
		a := b[block*8192+12+slot*252 : block*8192+12+(slot+1)*252]
		be.PutUint32(a, flags)
		be.PutUint32(a[12:], uint32(index))
		be.PutUint64(a[20:], size)
		for off := 48; off < 96; off += 4 {
			be.PutUint32(a[off:], 0xffffffff)
		}
		return a
	}
	a := anode(8, 1, 1, 0xb4052100, 8192)
	be.PutUint32(a[48:], 8)
	a = anode(8, 5, 5, 0xb4012280, 3*8192)
	be.PutUint32(a[48:], 9)
	be.PutUint32(a[56:], 13)
	for _, block := range []int{9, 13} {
		be.PutUint32(b[block*8192+4:], 0xb7afc1db)
		be.PutUint32(b[block*8192+8:], 5)
	}
	copy(b[9*8192+24:], eb("TEST", 4))
	inode := func(block, index, slot int, flags uint32, size uint64, kind uint32) []byte {
		a := anode(block, index, slot, flags, size)
		copy(a[100:], eb("IFSP", 4))
		a[104] = 1
		be.PutUint32(a[196:], 7)
		be.PutUint32(a[228:], 1)
		be.PutUint32(a[240:], kind)
		return a
	}
	a = inode(9, 2, 2, 0xb4112f98, 384, 1)
	be.PutUint32(a[48:], 10)
	be.PutUint32(a[52:], 0x30001)
	a = inode(9, 3, 3, 0xb4082f98, 4, 5)
	copy(a[48:], []byte{0x4b, 0x4b, 0x61, 0xc1})
	a = inode(9, 4, 4, 0xb4002f98, 0, 2)
	be.PutUint32(a[232:], 9)
	a = inode(13, 64, 0, 0xb4002f98, 8*8192+3, 3)
	be.PutUint32(a[80:], 12)
	a[240], a[241], a[242] = 3, 0x33, 0x80 // Tagged text: these bytes are not the inode type.
	indirect := b[12*8192 : 13*8192]
	be.PutUint32(indirect, 123)
	be.PutUint32(indirect[8192-4:], 123)
	be.PutUint32(indirect[4:], 0x5a308d31)
	be.PutUint32(indirect[16:], 8)
	be.PutUint32(indirect[20:], 1)
	be.PutUint32(indirect[24:], 2040)
	be.PutUint32(indirect[28:], 14)
	copy(b[14*8192:], "end")
	d := b[10*8192+3*1024:]
	be.PutUint32(d, 0x2c70bf7f)
	d[32] = 5
	for j, x := range []struct {
		name  string
		vnode uint32
	}{{".", 1}, {"..", 1}, {"FILE", 31}, {"LINK", 2}, {"DEV", 3}, {"LOOP", 1}} {
		off := (5 + j) * 32
		be.PutUint32(d[off:], 0x76e694c1)
		be.PutUint32(d[off+4:], x.vnode)
		be.PutUint32(d[off+8:], 7)
		if j < 5 {
			d[off+12] = byte(6 + j)
		}
		d[off+13] = 1
		d[off+14] = 1
		copy(d[off+15:], eb(x.name, len(x.name)))
	}
	// Restored names may have an unspecified (zero) generation.
	be.PutUint32(d[7*32+8:], 0)
	// Stale unlinked entry with convincing magic must never be exposed.
	be.PutUint32(d[11*32:], 0x76e694c1)
	be.PutUint32(d[11*32+4:], 999)
	return b
}
func TestEpisodeLogicalTreeAndSparseFile(t *testing.T) {
	b := episodeFixture()
	z, err := OpenEpisode(raw(b), 100)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := z.Filesets()
	if err != nil || len(fs) != 1 {
		t.Fatal(fs, err)
	}
	entries, err := fs[0].view(1, nil).Entries()
	if err != nil || len(entries) != 4 {
		t.Fatal(entries, err)
	}
	for _, e := range entries {
		switch e.Name {
		case "FILE":
			got := bytes.Repeat([]byte{255}, 7)
			n, err := e.Reader.ReadAt(got, 8*8192-2)
			if n != 5 || err != io.EOF || !bytes.Equal(got[:n], []byte{0, 0, 'e', 'n', 'd'}) {
				t.Fatal(n, err, got)
			}
		case "LINK":
			if e.Reader != nil || e.Attributes["link"] != "../A" {
				t.Fatal(e)
			}
		case "DEV":
			if e.Kind != "character-device" || e.Reader != nil {
				t.Fatal(e)
			}
		case "LOOP":
			if _, err := e.View.Entries(); err == nil {
				t.Fatal("cycle accepted")
			}
		}
	}
}
func TestEpisodeRejectsCorruptDirectoryAndStorage(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"stale generation", func(b []byte) { be.PutUint32(b[10*8192+3072+7*32+8:], 8) }},
		{"hash cycle", func(b []byte) { b[10*8192+3072+7*32+12] = 7 }},
		{"overlapping slots", func(b []byte) { b[10*8192+3072+7*32+13] = 2 }},
		{"bad metadata page", func(b []byte) { be.PutUint32(b[13*8192+8:], 6) }},
		{"bad indirect stamp", func(b []byte) { be.PutUint32(b[12*8192+8192-4:], 999) }},
		{"bad fragment range", func(b []byte) { be.PutUint32(b[9*8192+12+2*252+52:], 0x80001) }},
		{"huge file", func(b []byte) { be.PutUint64(b[13*8192+12+20:], math.MaxInt64) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := episodeFixture()
			tt.mutate(b)
			z, err := OpenEpisode(raw(b), 100)
			if err != nil {
				t.Fatal(err)
			}
			fs, err := z.Filesets()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fs[0].view(1, nil).Entries(); err == nil {
				t.Fatal("corruption accepted")
			}
		})
	}
}
func TestEpisodeDoubleIndirect(t *testing.T) {
	b := make([]byte, 6*8192)
	e := &Episode{source: raw(b), block: 8192, fragment: 1024, blocks: 5, limit: 100}
	a := episodeAnode{raw: make([]byte, 252)}
	be.PutUint32(a.raw, 0xb4002f98)
	be.PutUint64(a.raw[20:], uint64((8+2040)*8192+4))
	for i := 48; i < 96; i += 4 {
		be.PutUint32(a.raw[i:], 0xffffffff)
	}
	be.PutUint32(a.raw[84:], 1)
	for _, p := range []struct{ block, base, stride, child uint32 }{{1, 2048, 2040, 2}, {2, 2048, 1, 3}} {
		page := b[p.block*8192:]
		be.PutUint32(page, 7)
		be.PutUint32(page[8188:], 7)
		be.PutUint32(page[4:], 0x5a308d31)
		be.PutUint32(page[16:], p.base)
		be.PutUint32(page[20:], p.stride)
		be.PutUint32(page[24:], 2040)
		be.PutUint32(page[28:], p.child)
	}
	copy(b[3*8192:], "tail")
	data, err := e.content(a)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 8)
	n, err := data.ReadAt(got, (8+2040)*8192-4)
	if n != 8 || err != nil || !bytes.Equal(got, []byte{0, 0, 0, 0, 't', 'a', 'i', 'l'}) {
		t.Fatal(n, err, got)
	}
	be.PutUint32(b[2*8192+28:], 0x80000003)
	if _, err := e.content(a); err == nil {
		t.Fatal("backing pointer accepted")
	}
}
