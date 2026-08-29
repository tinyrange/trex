package windows

import (
	"encoding/binary"
	"testing"
)

func syntheticAuthenticodePE() []byte {
	data := make([]byte, 0x280)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:0x40], 0x80)
	copy(data[0x80:], "PE\x00\x00")
	coff := 0x84
	binary.LittleEndian.PutUint16(data[coff:coff+2], 0x14c)
	binary.LittleEndian.PutUint16(data[coff+2:coff+4], 2)
	binary.LittleEndian.PutUint16(data[coff+16:coff+18], 0xe0)
	optional := 0x98
	binary.LittleEndian.PutUint16(data[optional:optional+2], 0x10b)
	binary.LittleEndian.PutUint32(data[optional+60:optional+64], 0x200)
	binary.LittleEndian.PutUint32(data[optional+64:optional+68], 0x12345678)
	binary.LittleEndian.PutUint32(data[optional+92:optional+96], 16)
	security := optional + 96 + 4*8
	binary.LittleEndian.PutUint32(data[security:security+4], 0x260)
	binary.LittleEndian.PutUint32(data[security+4:security+8], 0x10)

	sections := optional + 0xe0
	copy(data[sections:], ".late")
	binary.LittleEndian.PutUint32(data[sections+16:sections+20], 0x10)
	binary.LittleEndian.PutUint32(data[sections+20:sections+24], 0x240)
	copy(data[sections+40:], ".early")
	binary.LittleEndian.PutUint32(data[sections+56:sections+60], 0x20)
	binary.LittleEndian.PutUint32(data[sections+60:sections+64], 0x200)
	for index := 0x200; index < len(data); index++ {
		data[index] = byte(index)
	}
	return data
}

func TestWindowsCatalogHashUsesAuthenticodePERanges(t *testing.T) {
	data := syntheticAuthenticodePE()
	want, err := windowsCatalogHash(data, "sha1")
	if err != nil {
		t.Fatal(err)
	}

	for _, offset := range []int{0x98 + 64, 0x98 + 96 + 4*8, 0x260, 0x278} {
		modified := append([]byte(nil), data...)
		modified[offset] ^= 0xff
		got, err := windowsCatalogHash(modified, "sha1")
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("excluded byte at %#x changed Authenticode hash", offset)
		}
	}

	modified := append([]byte(nil), data...)
	modified[0x210] ^= 0xff
	got, err := windowsCatalogHash(modified, "sha1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == string(want) {
		t.Fatal("section mutation did not change Authenticode hash")
	}
}

func TestWindowsCatalogHashFallsBackToFlatDigest(t *testing.T) {
	for _, data := range [][]byte{[]byte("catalog member"), append([]byte("MZ"), make([]byte, 62)...)} {
		got, err := windowsCatalogHash(data, "sha256")
		if err != nil {
			t.Fatal(err)
		}
		h, err := authenticodeHasher("sha256")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = h.Write(data)
		want := h.Sum(nil)
		if string(got) != string(want) {
			t.Fatalf("catalog hash = %x, want %x", got, want)
		}
	}
}
