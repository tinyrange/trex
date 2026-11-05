package windows

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// A legacy image may use a larger file alignment than SizeOfHeaders. The
// signed catalog digest of msvbvm60.dll (26100.1) includes this header padding,
// then contiguous physical sections and the debug overlay before its cert.
func TestCatalogHashIncludesPhysicalHeaderPadding(t *testing.T) {
	data := syntheticAuthenticodePE()
	// Move both sections beyond a nonempty header gap, retaining reverse
	// section-table order. Follow them with overlay, cert, and more overlay.
	binary.LittleEndian.PutUint32(data[0x178+20:], 0x240)
	binary.LittleEndian.PutUint32(data[0x178+60:], 0x220)
	expected := append([]byte(nil), data[:0xd8]...)
	expected = append(expected, data[0xdc:0x118]...)
	expected = append(expected, data[0x120:0x260]...)
	expected = append(expected, data[0x270:]...)
	want := sha256.Sum256(expected)
	got, err := windowsCatalogHash(data, "sha256")
	if err != nil || !bytes.Equal(got, want[:]) {
		t.Fatalf("header-padding digest = %x, %v; want %x", got, err, want)
	}
	// Neither a flat digest of only mapped sections nor appending extra data
	// at SizeOfHeaders+sum(raw sizes) covers the header gap correctly.
	data[0x210] ^= 1
	changed, err := windowsCatalogHash(data, "sha256")
	if err != nil || bytes.Equal(got, changed) {
		t.Fatalf("physical header padding not covered: %x, %v", changed, err)
	}
	mapped, err := authenticodePERanges(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, region := range mapped {
		if region.offset <= 0x210 && region.offset+region.size > 0x210 {
			t.Fatal("catalog-only header padding leaked into mapped page ranges")
		}
	}
}
