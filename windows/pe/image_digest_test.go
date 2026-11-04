package pe

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"testing"
)

func imageDigestFixture(wide bool) ([]byte, int, int, int) {
	data := make([]byte, 0x500)
	for i := range data {
		data[i] = byte(i*13 + 7)
	}
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[60:], 0x80)
	nt, optional := 0x80, 0x98
	size, magic := 224, uint16(0x10b)
	if wide {
		size, magic = 240, 0x20b
	}
	clear(data[nt : optional+size+160])
	copy(data[nt:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(data[nt+6:], 4)
	binary.LittleEndian.PutUint16(data[nt+20:], uint16(size))
	binary.LittleEndian.PutUint16(data[optional:], magic)
	data[optional+2] = 14
	dirs := optional + size - 128
	binary.LittleEndian.PutUint32(data[dirs-4:], 16)
	for _, p := range []int{optional + 8, optional + 56, optional + 64} {
		binary.LittleEndian.PutUint32(data[p:], 0xabcdef)
	}
	for i, v := range []uint32{0x2000, 16, 0, 0, 0x480, 32, 0x3000, 16} {
		binary.LittleEndian.PutUint32(data[dirs+16+i*4:], v)
	}
	table := optional + size
	names := []string{".text", ".rsrc", ".reloc", ".debug"}
	for i, off := range []uint32{0x400, 0x420, 0x450, 0x470} {
		h := data[table+40*i : table+40*(i+1)]
		copy(h, names[i])
		binary.LittleEndian.PutUint32(h[8:], 32)
		binary.LittleEndian.PutUint32(h[12:], uint32(i+1)*0x1000)
		raw := uint32(16)
		if i == 1 {
			raw = 32
		}
		binary.LittleEndian.PutUint32(h[16:], raw)
		binary.LittleEndian.PutUint32(h[20:], off)
	}
	return data, optional, dirs, table
}

func TestImageDigestNativeStream(t *testing.T) {
	for _, wide := range []bool{false, true} {
		data, opt, dirs, table := imageDigestFixture(wide)
		// Independent expected serialized stream: fixed headers with native field
		// normalization, no header padding, resource bytes or debug payload, and
		// section payloads in table order (including resource raw padding).
		header := append([]byte(nil), data[:table+160]...)
		for _, p := range []int{opt + 8, opt + 56, opt + 64, dirs + 16, dirs + 20, dirs + 32, dirs + 36, dirs + 40, table + 80 + 12, table + 80 + 20} {
			clear(header[p : p+4])
		}
		clear(header[table+40+8 : table+40+24])
		clear(header[table+120+8 : table+120+24])
		expected := append(header, data[0x400:0x410]...)
		expected = append(expected, data[0x430:0x440]...)
		expected = append(expected, data[0x450:0x460]...)
		want := sha1.Sum(expected)
		digest := func(input []byte) []byte {
			t.Helper()
			h := sha1.New()
			if err := ImageDigest(input, h); err != nil {
				t.Fatal(err)
			}
			return h.Sum(nil)
		}
		if got := digest(data); !bytes.Equal(got, want[:]) {
			t.Fatalf("wide=%v stream mismatch: %x != %x", wide, got, want)
		}
		for _, pos := range []int{opt + 8, opt + 56, opt + 64, 0x410, 0x420, 0x470, 0x490} {
			changed := append([]byte(nil), data...)
			changed[pos] ^= 0x55
			if !bytes.Equal(digest(changed), want[:]) {
				t.Fatalf("excluded byte %x affected digest", pos)
			}
		}
		for _, pos := range []int{0x20, 0x400, 0x430, 0x450} {
			changed := append([]byte(nil), data...)
			changed[pos] ^= 0x55
			if bytes.Equal(digest(changed), want[:]) {
				t.Fatalf("included byte %x ignored", pos)
			}
		}
		for n := 2; n < 0x480; n++ {
			h := sha1.New()
			if err := ImageDigest(data[:n], h); err == nil {
				t.Fatalf("accepted truncation %x wide=%v", n, wide)
			}
			if !bytes.Equal(h.Sum(nil), sha1.New().Sum(nil)) {
				t.Fatal("error wrote partial digest")
			}
		}
		for _, pos := range []int{60, dirs + 16, table + 16, table + 20} {
			changed := append([]byte(nil), data...)
			binary.LittleEndian.PutUint32(changed[pos:], 0xffffffff)
			if err := ImageDigest(changed, sha1.New()); err == nil {
				t.Fatalf("accepted invalid range at %x", pos)
			}
		}
		overlap := append([]byte(nil), data...)
		binary.LittleEndian.PutUint32(overlap[table+40+20:], 0x400)
		if err := ImageDigest(overlap, sha1.New()); err == nil {
			t.Fatal("accepted overlapping sections")
		}
	}
}

func TestImageDigestNonImageAndShortOptionalHeader(t *testing.T) {
	h := sha1.New()
	data := []byte("ordinary file")
	if err := ImageDigest(data, h); err != nil {
		t.Fatal(err)
	}
	want := sha1.Sum(data)
	if !bytes.Equal(h.Sum(nil), want[:]) {
		t.Fatal("non-image hash changed")
	}
	data, _, _, _ = imageDigestFixture(false)
	binary.LittleEndian.PutUint16(data[0x80+20:], 2)
	if err := ImageDigest(data[:0x98+2], sha1.New()); err == nil {
		t.Fatal("accepted short optional header")
	}
}
