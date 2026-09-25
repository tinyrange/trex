package floppy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/tinyrange/trex/auto"
	_ "github.com/tinyrange/trex/filesystem/fat"
)

func put16(b []byte, off, v int) { binary.LittleEndian.PutUint16(b[off:], uint16(v)) }
func ddi() []byte {
	b := make([]byte, 3*4608)
	copy(b, ddiMagic)
	b[10] = 1
	b[100] = 1
	b[101] = 2 // Deliberately non-monotonic storage order.
	b[106] = 1
	b[107] = 1
	for i := 4608; i < 9216; i++ {
		b[i] = 0x22
	}
	for i := 9216; i < len(b); i++ {
		b[i] = 0x11
	}
	return b
}
func TestDiskDupeReads(t *testing.T) {
	b := ddi()
	f, e := OpenDiskDupe(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	p := make([]byte, 4)
	if n, e := f.ReadAt(p, 4606); n != 4 || e != nil || !bytes.Equal(p, []byte{17, 17, 34, 34}) {
		t.Fatalf("boundary %x %d %v", p, n, e)
	}
	if n, e := f.ReadAt(p, 9214); n != 2 || !errors.Is(e, ErrMissingTrack) {
		t.Fatalf("missing %d %v", n, e)
	}
	if n, e := f.ReadAt(p, f.Size()); n != 0 || e != io.EOF {
		t.Fatalf("EOF %d %v", n, e)
	}
	if _, e := f.ReadAt(p, -1); e == nil {
		t.Fatal("negative offset accepted")
	}
	if _, e := f.WriteAt(p, 0); e == nil {
		t.Fatal("write accepted")
	}
	for _, mutate := range []func([]byte){func(b []byte) { b[10] = 5 }, func(b []byte) { b[100] = 2 }, func(b []byte) { b[101] = 0 }, func(b []byte) { b[107] = 2 }, func(b []byte) { b[101] = 255 }, func(b []byte) { b[102] = 1 }} {
		b := ddi()
		mutate(b)
		if _, e := OpenDiskDupe(bytes.NewReader(b)); e == nil {
			t.Fatal("malformed DDI accepted")
		}
	}
	if _, e := OpenDiskDupe(bytes.NewReader(b[:500])); e == nil {
		t.Fatal("truncated map accepted")
	}
}
func hd(extended bool) []byte {
	b := make([]byte, 166)
	b[0] = 39
	b[1] = 9
	b[2] = 1
	b[3] = 1
	if extended {
		b = make([]byte, 184)
		b[0] = 255
		b[1] = 24
		b[14] = 83
		b[15] = 9
		b[16] = 1
		b[17] = 1
	}
	for track := 0; track < 2; track++ {
		block := []byte{0x90, byte(track + 1)} // One literal, then repeated runs.
		for left := 4607; left > 0; {
			n := min(left, 255)
			block = append(block, 0x90, byte(track+1), byte(n))
			left -= n
		}
		b = append(b, byte(len(block)), byte(len(block)>>8))
		b = append(b, block...)
	}
	return b
}
func TestHDCopy(t *testing.T) {
	for _, extended := range []bool{false, true} {
		b := hd(extended)
		f, e := OpenHDCopy(bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		p := make([]byte, 4)
		n, e := f.ReadAt(p, 4606)
		if n != 4 || e != nil || !bytes.Equal(p, []byte{1, 1, 2, 2}) {
			t.Fatalf("RLE boundary %x %d %v", p, n, e)
		}
		if _, e = f.ReadAt(p, 9216); !errors.Is(e, ErrMissingTrack) {
			t.Fatal(e)
		}
		if _, e = OpenHDCopy(bytes.NewReader(b[:len(b)-1])); e == nil {
			t.Fatal("truncated block accepted")
		}
		result, e := auto.Identify(bytes.NewReader(b), auto.Options{})
		if e != nil || result.Format != "hdcopy" {
			t.Fatalf("detect %v %v", result, e)
		}
	}
	for _, b := range [][]byte{{0x90}, {0x90, 1}, {0x90, 1, 0}, {0x90, 1, 5}, {1, 2}} {
		if _, e := decodeTrack(b, 0x90, 4); e == nil {
			t.Fatalf("bad RLE accepted %x", b)
		}
	}
	if b, e := decodeTrack([]byte{0x90, 0x90, 4}, 0x90, 4); e != nil || !bytes.Equal(b, bytes.Repeat([]byte{0x90}, 4)) {
		t.Fatalf("escaped escape %x %v", b, e)
	}
}
func dup() []byte {
	b := make([]byte, 1536)
	copy(b, duplicatorMagic)
	put16(b, 64, 1)
	put16(b, 66, 1)
	put16(b, 68, 2)
	put16(b, 70, 2)
	put16(b, 100, 1)
	put16(b, 106, 2)
	b[110] = 0xe5
	for i := 512; i < len(b); i++ {
		b[i] = 0x33
	}
	return b
}
func TestDuplicator(t *testing.T) {
	b := dup()
	f, e := OpenDuplicator(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	p := make([]byte, 4)
	n, e := f.ReadAt(p, 1022)
	if n != 4 || e != nil || !bytes.Equal(p, []byte{0x33, 0x33, 0xe5, 0xe5}) {
		t.Fatalf("filler %x %d %v", p, n, e)
	}
	if n, e := f.ReadAt(p, 2046); n != 2 || e != io.EOF {
		t.Fatalf("short EOF %d %v", n, e)
	}
	for _, mutate := range []func([]byte){func(b []byte) { put16(b, 64, 2) }, func(b []byte) { put16(b, 66, 3) }, func(b []byte) { put16(b, 106, 3) }, func(b []byte) { put16(b, 106, 0); put16(b, 108, 2) }} {
		b := dup()
		mutate(b)
		if _, e := OpenDuplicator(bytes.NewReader(b)); e == nil {
			t.Fatal("bad cylinder accepted")
		}
	}
}

// A tiny FAT12 volume with its directory and one allocated cluster in the two
// stored tracks. All later tracks are omitted. Detection used to pre-read 64K.
func TestSparseFATBrowsing(t *testing.T) {
	b := ddi()
	boot := b[9216:]
	clear(boot)
	clear(b[4608:9216])
	boot[0] = 0xeb
	put16(boot, 11, 512)
	boot[13] = 1
	put16(boot, 14, 1)
	boot[16] = 2
	put16(boot, 17, 16)
	put16(boot, 19, 720)
	boot[21] = 0xfd
	put16(boot, 22, 3)
	put16(boot, 24, 9)
	put16(boot, 26, 2)
	boot[510] = 0x55
	boot[511] = 0xaa
	for _, off := range []int{512, 2048} {
		copy(boot[off:], []byte{0xfd, 0xff, 0xff, 0xff, 0x0f})
	}
	copy(boot[3584:], "HELLO   TXT")
	boot[3595] = 0x20
	put16(boot, 3610, 2)
	binary.LittleEndian.PutUint32(boot[3612:], 5)
	copy(boot[4096:], "hello")
	root := auto.Open(bytes.NewReader(b), "test.ddi", auto.Options{})
	m, e := root.Metadata()
	if e != nil || m.Format != "diskdupe" || m.Attributes["omitted_units"] != 78 {
		t.Fatalf("metadata %+v %v", m, e)
	}
	children, e := root.Children()
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, c := range children {
		if c.Name() == "HELLO.TXT" {
			p := make([]byte, 5)
			n, e := c.Reader().ReadAt(p, 0)
			if n != 5 || e != nil || string(p) != "hello" {
				t.Fatalf("content %q %d %v", p, n, e)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("missing HELLO.TXT")
	}
	if _, _, _, _, e := root.ChildPage(0, 10); e != nil {
		t.Fatal(e)
	}
	// Trimming an unused raw tail is also safe; allocated content still reads.
	raw := append(append([]byte{}, boot...), b[4608:9216]...)
	if _, e := auto.Open(bytes.NewReader(raw), "trimmed.img", auto.Options{}).Children(); e != nil {
		t.Fatal(e)
	}
}
