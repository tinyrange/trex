package acpi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPCIRootMemoryDescriptorWidth(t *testing.T) {
	for _, tc := range []struct {
		base, size uint64
		width      int
		tag        byte
	}{
		{0xc0000000, 0x3ec00000, 4, 0x87},
		{0x100000000, 0x20000000, 8, 0x8a},
		{0, 0x100000000, 8, 0x8a}, // A 4 GiB length cannot fit a DWord.
	} {
		aml, err := (PCIRoot{Legacy: true, MemoryBase: tc.base, MemorySize: tc.size}).AML()
		if err != nil {
			t.Fatal(err)
		}
		// Find the fixed memory producer descriptor, independently decode all
		// address fields, and verify no truncation at the width boundary.
		prefix := []byte{tc.tag, byte(3 + 5*tc.width), 0, 0, 0x0c, 1}
		at := bytes.Index(aml, prefix)
		if at < 0 {
			t.Fatal("missing memory producer descriptor", tc)
		}
		fields := aml[at+6 : at+6+5*tc.width]
		read := func(n int) uint64 {
			if tc.width == 4 {
				return uint64(binary.LittleEndian.Uint32(fields[n*4:]))
			}
			return binary.LittleEndian.Uint64(fields[n*8:])
		}
		if read(0) != 0 || read(1) != tc.base || read(2) != tc.base+tc.size-1 || read(3) != 0 || read(4) != tc.size {
			t.Fatal("resource address fields truncated", tc)
		}
	}
}
