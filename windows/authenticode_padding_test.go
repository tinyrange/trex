package windows

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestCatalogHashPadsUnalignedPEOverlay(t *testing.T) {
	for remainder := 0; remainder < 8; remainder++ {
		data := syntheticAuthenticodePE()
		// Use contiguous sections, no certificate table, and a physical
		// length covering every possible trailing alignment remainder.
		data[0x178+20] = 0x20
		clear(data[0x118:0x120])
		data = append(data, bytes.Repeat([]byte{0xa5}, remainder)...)
		padded := append([]byte(nil), data...)
		for len(padded)%8 != 0 {
			padded = append(padded, 0)
		}
		stream := append([]byte(nil), padded[:0xd8]...)
		stream = append(stream, padded[0xdc:0x118]...)
		stream = append(stream, padded[0x120:]...)
		want := sha256.Sum256(stream)
		got, err := windowsCatalogHash(data, "sha256")
		if err != nil || !bytes.Equal(got, want[:]) {
			t.Fatalf("remainder %d: digest %x, %v; want %x", remainder, got, err, want)
		}
		physicallyPadded, err := windowsCatalogHash(padded, "sha256")
		if err != nil || !bytes.Equal(got, physicallyPadded) {
			t.Fatalf("virtual/physical padding differ at remainder %d: %v", remainder, err)
		}
	}
	// Ordinary catalog members do not inherit the PE-only padding rule.
	plain := []byte("abc")
	got, err := windowsCatalogHash(plain, "sha256")
	want := sha256.Sum256(plain)
	if err != nil || !bytes.Equal(got, want[:]) {
		t.Fatalf("non-PE unexpectedly padded: %x, %v", got, err)
	}
}
