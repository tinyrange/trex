package darwin

import (
	"bytes"
	"encoding/binary"
	"hash/adler32"
	"strings"
	"testing"
)

type source struct{ *bytes.Reader }

func (s source) Size() int64 { return s.Reader.Size() }
func fixture() []byte {
	b := make([]byte, 4096)
	p := binary.LittleEndian.PutUint32
	q := binary.LittleEndian.PutUint64
	p(b, 0xfeedfacf)
	p(b[4:], 0x01000007)
	p(b[12:], 2)
	p(b[16:], 2)
	p(b[20:], 72+184)
	c := b[32:]
	p(c, 0x19)
	p(c[4:], 72)
	copy(c[8:], "__TEXT")
	q(c[24:], kernelBase+0x200000)
	q(c[32:], 8192)
	q(c[48:], 4096)
	p(c[56:], 7)
	p(c[60:], 5)
	c = b[104:]
	p(c, 5)
	p(c[4:], 184)
	p(c[8:], 4)
	p(c[12:], 42)
	q(c[144:], kernelBase+0x200200)
	b[512] = 0xfa
	return b
}
func packed(b []byte) []byte {
	out := make([]byte, 384)
	copy(out, "complzss")
	binary.BigEndian.PutUint32(out[8:], adler32.Checksum(b))
	binary.BigEndian.PutUint32(out[12:], uint32(len(b)))
	for off := 0; off < len(b); off += 8 {
		n := min(8, len(b)-off)
		out = append(out, byte((1<<n)-1))
		out = append(out, b[off:off+n]...)
	}
	binary.BigEndian.PutUint32(out[16:], uint32(len(out)-384))
	return out
}
func TestWrappedKernelAndZeroFill(t *testing.T) {
	cache := packed(fixture())
	fat := make([]byte, 4096)
	binary.BigEndian.PutUint32(fat, 0xcafebabe)
	binary.BigEndian.PutUint32(fat[4:], 1)
	binary.BigEndian.PutUint32(fat[8:], 0x01000007)
	binary.BigEndian.PutUint32(fat[16:], 4096)
	binary.BigEndian.PutUint32(fat[20:], uint32(len(cache)))
	fat = append(fat, cache...)
	img, err := Open(source{bytes.NewReader(fat)})
	if err != nil {
		t.Fatal(err)
	}
	if img.Entry != 0x200200 || img.Base != 0x200000 || img.End != 0x202000 {
		t.Fatalf("wrong layout: %+v", img)
	}
	ram := bytes.Repeat([]byte{0xcc}, 0x202000)
	if err = img.Load(ram); err != nil {
		t.Fatal(err)
	}
	if ram[0x200200] != 0xfa || ram[0x201000] != 0 || ram[0x1fffff] != 0xcc {
		t.Fatal("load or zero fill changed the wrong bytes")
	}
	short := bytes.Repeat([]byte{0xcc}, 4096)
	before := bytes.Clone(short)
	if img.Load(short) == nil || !bytes.Equal(short, before) {
		t.Fatal("short RAM modified")
	}
	fat[len(fat)-1] ^= 1
	if _, err = Open(source{bytes.NewReader(fat)}); err == nil || !strings.Contains(err.Error(), "Adler") {
		t.Fatalf("corruption accepted: %v", err)
	}
}
func TestMalformedKernel(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]byte)
	}{
		{"commands", func(b []byte) { binary.LittleEndian.PutUint32(b[20:], 0xffffffff) }},
		{"entry", func(b []byte) { binary.LittleEndian.PutUint64(b[104+144:], kernelBase+0x202000) }},
		{"segment", func(b []byte) { binary.LittleEndian.PutUint64(b[32+48:], 8193) }},
		{"thread", func(b []byte) { binary.LittleEndian.PutUint32(b[104+12:], 41) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := fixture()
			c.mutate(b)
			if _, err := Open(source{bytes.NewReader(b)}); err == nil {
				t.Fatal("accepted invalid kernel")
			}
		})
	}
}
func TestLZSSOverlapAndBounds(t *testing.T) {
	// One literal 'A', followed by two overlapping matches to that ring slot.
	src := []byte{1, 'A', 0xee, 0xff, 0x00, 0x0a}
	out, err := decodeLZSS(src, 32)
	if err != nil || string(out) != strings.Repeat("A", 32) {
		t.Fatalf("overlap: %q %v", out, err)
	}
	for _, bad := range [][]byte{src[:len(src)-1], append(bytes.Clone(src), 0)} {
		if _, err = decodeLZSS(bad, 32); err == nil {
			t.Fatal("accepted bad length")
		}
	}
	if _, err = decodeLZSS(src, 31); err == nil {
		t.Fatal("accepted unbounded decoded length")
	}
}

func TestLoadRejectsChangedImageAtomically(t *testing.T) {
	img, err := Open(source{bytes.NewReader(fixture())})
	if err != nil {
		t.Fatal(err)
	}
	img.Segments = append(img.Segments, Segment{Address: 0x202000, Size: 4096, FileSize: 1, FileOffset: ^uint64(0)})
	ram := bytes.Repeat([]byte{0xcc}, 0x203000)
	before := bytes.Clone(ram)
	if img.Load(ram) == nil || !bytes.Equal(ram, before) {
		t.Fatal("invalid exported image partially loaded")
	}
}
func TestZeroVMCTFFileSegment(t *testing.T) {
	b := fixture()
	p := binary.LittleEndian.PutUint32
	q := binary.LittleEndian.PutUint64
	p(b[16:], 3)
	p(b[20:], 328)
	c := b[288:]
	p(c, 0x19)
	p(c[4:], 72)
	copy(c[8:], "__CTF")
	q(c[40:], 1024)
	q(c[48:], 128)
	img, err := Open(source{bytes.NewReader(b)})
	if err != nil || len(img.Segments) != 1 {
		t.Fatal("valid file-only CTF segment rejected", err)
	}
}
