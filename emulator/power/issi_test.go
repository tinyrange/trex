package power

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestISSIEncodeCapturesHiddenTagsBeforeStamp(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Extensions: []string{"as"}})
	c := m.CPUs[0]
	const sidecar, headers, page = 0x2000, 0x3000, 0x4000
	for i := 0; i < 4096; i++ {
		m.Mem[page+i] = byte(i * 7)
	}
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint64(m.Mem[headers+i*8:], 0x0011223344556600)
	}
	// Sector0 first/last pointer, sector1 interior pointer, sector7 last.
	for _, q := range []uint64{0, 31, 32 + 5, 255} {
		m.tags[(page/16+q)/64] |= 1 << ((page/16 + q) % 64)
	}
	original := bytes.Clone(m.Mem[page : page+4096])
	if err := c.EncodeISSI(sidecar, headers, page, 123, 3); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Mem[page:page+4096], original) {
		t.Fatal("save modified data")
	}
	for i, want := range []uint32{0x80000001, 0x04000000, 0, 0, 0, 0, 0, 1} {
		h := m.Mem[headers+i*8 : headers+(i+1)*8]
		if want != 0 {
			if binary.BigEndian.Uint32(h[3:]) != want || h[7]&8 == 0 {
				t.Fatal("tag header", i, h)
			}
		} else if !bytes.Equal(h, []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0}) {
			t.Fatal("untagged header changed", i, h)
		}
	}
	saved := bytes.Clone(m.Mem[sidecar+8 : sidecar+136])
	if err := c.EncodeISSI(sidecar, headers, page, 0x123456789, 4); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Mem[sidecar+8:sidecar+136], saved) {
		t.Fatal("stamp altered saved words")
	}
	if m.Tag(page+31*16) || !m.Tag(page) || !m.Tag(page+37*16) {
		t.Fatal("ordinary control stores must clear only overlapping tags")
	}
	// A real device read clears all destination tags. Decode must recover
	// both the displaced pointer bytes and the saved hidden tag bitmap.
	encoded := bytes.Clone(m.Mem[page : page+4096])
	if err := m.WriteReal(page, encoded); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(m.Mem[page+504:], 0xdeadbeef)
	if err := c.DecodeISSI(sidecar, headers, page, 3); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Mem[page:page+4096], original) {
		t.Fatal("decode lost original bytes")
	}
	for q := uint64(0); q < 256; q++ {
		want := q == 0 || q == 31 || q == 37 || q == 255
		if m.Tag(page+q*16) != want {
			t.Fatal("restored hidden tag", q)
		}
	}
	if binary.BigEndian.Uint64(m.Mem[sidecar+136:]) != 0xdeadbeef {
		t.Fatal("decode hid mismatching received control")
	}
	before := bytes.Clone(m.Mem)
	for _, r := range [][5]uint64{{sidecar, headers, page, 0, 4}, {sidecar, headers, page, 1, 8}, {sidecar, headers, page + 8, 1, 3}, {sidecar, sidecar, page, 1, 3}, {sidecar, headers, (1 << 20) - 4096 + 16, 1, 3}} {
		if c.EncodeISSI(r[0], r[1], r[2], r[3], uint32(r[4])) == nil || !bytes.Equal(m.Mem, before) {
			t.Fatal("invalid encode not atomic", r)
		}
	}
	if c.DecodeISSI(sidecar, headers, page, 4) == nil || !bytes.Equal(m.Mem, before) {
		t.Fatal("invalid decode mutated state")
	}
}

func TestISSIDecodeTagsRequireASBeforeMutation(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20})
	c := m.CPUs[0]
	m.Mem[0x2000+8+3] = 0x80
	m.Mem[0x2000+8+7] = 8
	before := bytes.Clone(m.Mem)
	if c.DecodeISSI(0x2000, 0x3000, 0x4000, 3) == nil || !bytes.Equal(before, m.Mem) {
		t.Fatal("unsupported tags were discarded or modified state")
	}
}

func TestISSIDecodeControlsWithoutRestoringTags(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Extensions: []string{"as"}})
	c := m.CPUs[0]
	const sidecar, headers, page = 0x2000, 0x3000, 0x4000
	// The saved header requests a tag at quadword0, while the existing
	// memory tag is at quadword1. Flag2 must leave both alone.
	m.Mem[sidecar+8+3] = 0x80
	m.Mem[sidecar+8+7] = 8
	m.tags[(page/16+1)/64] |= 1 << ((page/16 + 1) % 64)
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint64(m.Mem[page+i*512+504:], uint64(i+100))
		binary.BigEndian.PutUint64(m.Mem[sidecar+72+i*8:], uint64(i+200))
	}
	if err := c.DecodeISSI(sidecar, headers, page, 2); err != nil {
		t.Fatal(err)
	}
	if m.Tag(page) || !m.Tag(page+16) {
		t.Fatal("flag2 restored or cleared an unrelated tag")
	}
	for i := 0; i < 8; i++ {
		if binary.BigEndian.Uint64(m.Mem[sidecar+136+i*8:]) != uint64(i+100) || binary.BigEndian.Uint64(m.Mem[page+i*512+504:]) != uint64(i+200) {
			t.Fatal("controls or displaced bytes", i)
		}
	}
}

func TestStandaloneTagCapturePreservesZeroHeadersAndRejectsBadRanges(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Extensions: []string{"as"}})
	c := m.CPUs[0]
	const headers, page = 0x3000, 0x4000
	// A zero sector bitmap must preserve even an existing tag-present header.
	for i := 0; i < 64; i++ {
		m.Mem[headers+i] = byte(i*3 + 7)
	}
	original := bytes.Clone(m.Mem[headers : headers+64])
	if err := c.CapturePageTags(headers, page); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, m.Mem[headers:headers+64]) {
		t.Fatal("zero bitmap changed an existing header")
	}
	before := bytes.Clone(m.Mem)
	for _, r := range [][2]uint64{{headers + 1, page}, {headers, page + 16}, {page + 16, page}, {(1 << 20) - 56, page}, {headers, 1 << 20}, {^uint64(7), page}} {
		if c.CapturePageTags(r[0], r[1]) == nil || !bytes.Equal(before, m.Mem) {
			t.Fatal("invalid capture mutated memory", r)
		}
	}
}
