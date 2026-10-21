package iso9660

import (
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

func hsRecord(name string, extent, size uint32, flags byte) []byte {
	p := testRecord(name, extent, size, 0)
	p[24] = flags
	return p
}

func hsDisc(blockSize int) []byte {
	b := make([]byte, 32*2048)
	for sector, typ := range map[int]byte{16: 1, 17: 255} {
		p := b[sector*2048:]
		copy(p, testBoth(uint32(sector)))
		p[8] = typ
		copy(p[9:], "CDROM")
		p[14] = 1
	}
	p := b[16*2048:]
	copy(p[88:], testBoth(uint32(len(b)/blockSize)))
	binary.LittleEndian.PutUint16(p[136:], uint16(blockSize))
	binary.BigEndian.PutUint16(p[138:], uint16(blockSize))
	root := uint32(20 * 2048 / blockSize)
	child := uint32(22 * 2048 / blockSize)
	data := uint32(24 * 2048 / blockSize)
	copy(p[180:], hsRecord("\x00", root, uint32(2*blockSize), 2))
	copy(b[20*2048:], testFields(hsRecord("\x00", root, uint32(2*blockSize), 2), hsRecord("\x01", root, uint32(2*blockSize), 2), hsRecord("DIR", child, uint32(blockSize), 2)))
	// A zero record skips to the next logical block, not necessarily sector.
	copy(b[20*2048+blockSize:], hsRecord("EMPTY.;1", data, 0, 0))
	file := hsRecord("HELLO.TXT;1", data-1, 5, 0)
	file[1] = 1  // Skip one extended-attribute block before reading file data.
	file[25] = 2 // Reserved in High Sierra; must not turn this into a directory.
	copy(b[22*2048:], testFields(hsRecord("\x00", child, uint32(blockSize), 2), file))
	copy(b[24*2048:], "hello")
	return b
}

func TestHighSierra(t *testing.T) {
	for _, blockSize := range []int{512, 1024, 2048} {
		t.Run(fmt.Sprint(blockSize), func(t *testing.T) {
			file := &starfile.Bytes{Data: hsDisc(blockSize)}
			img, err := newISOImage(file)
			if err != nil {
				t.Fatal(err)
			}
			if !img.highSierra || img.joliet || img.rockRidge || img.blockSize != int64(blockSize) {
				t.Fatal("wrong layout")
			}
			r, err := img.lookup("dir/hello.txt")
			if err != nil || r.isDir() {
				t.Fatal(r, err)
			}
			payload := &isoFile{image: img, record: r}
			got := make([]byte, 8)
			if n, err := payload.ReadAt(got, 1); n != 4 || err != io.EOF || string(got[:n]) != "ello" {
				t.Fatal(n, err, string(got))
			}
			entries, err := Entries(file)
			if err != nil || len(entries) != 3 {
				t.Fatal(entries, err)
			}
			identified, err := auto.Identify(file, auto.Options{})
			if err != nil || identified.Format != "high_sierra" {
				t.Fatal(identified, err)
			}
			children, err := identified.View.Entries()
			if err != nil || len(children) != 2 {
				t.Fatal(children, err)
			}
		})
	}
}

func TestHighSierraMalformed(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"descriptor address": func(b []byte) []byte { b[16*2048]++; return b },
		"descriptor version": func(b []byte) []byte { b[16*2048+14]++; return b },
		"mixed sequence":     func(b []byte) []byte { copy(b[17*2048+9:], "CD001"); return b },
		"block endian":       func(b []byte) []byte { b[16*2048+138]++; return b },
		"invalid block":      func(b []byte) []byte { copy(b[16*2048+136:], []byte{0, 1, 1, 0}); return b },
		"volume endian":      func(b []byte) []byte { b[16*2048+92]++; return b },
		"missing primary":    func(b []byte) []byte { b[16*2048+8] = 255; return b },
		"root flags":         func(b []byte) []byte { b[16*2048+180+24] = 0; return b },
		"root extent":        func(b []byte) []byte { copy(b[16*2048+182:], testBoth(100)); return b },
		"short source":       func(b []byte) []byte { return b[:len(b)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newISOImage(&starfile.Bytes{Data: mutate(hsDisc(2048))}); err == nil {
				t.Fatal("accepted malformed descriptor")
			}
		})
	}
	for _, offset := range []int{2, 6, 10, 14} {
		t.Run(fmt.Sprintf("record field %d", offset), func(t *testing.T) {
			b := hsDisc(2048)
			b[22*2048+34+offset] = 255
			if _, err := Entries(&starfile.Bytes{Data: b}); err == nil {
				t.Fatal("accepted malformed file extent")
			}
		})
	}
}

func TestISOIdentifierPrecedesHighSierraLookalike(t *testing.T) {
	b := testDisc(false, false)
	copy(b[16*2048+9:], "CDROM") // ISO system identifier may contain these bytes.
	file := &starfile.Bytes{Data: b}
	img, err := newISOImage(file)
	if err != nil || img.highSierra {
		t.Fatal(img, err)
	}
	identified, err := auto.Identify(file, auto.Options{})
	if err != nil || identified.Format != "iso9660" {
		t.Fatal(identified, err)
	}
}

func FuzzHighSierraRecord(f *testing.F) {
	f.Add(hsRecord("FILE;1", 22, 5, 0))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		img := &isoImage{highSierra: true, blockSize: 2048, volumeSize: 32 * 2048}
		_, _ = img.highSierraRecord(raw)
	})
}
