package acpi

import (
	"bytes"
	"testing"
)

func TestFixedMMIODeviceDeclaresLevelInterrupt(t *testing.T) {
	data, err := (ISADevice{
		Name: "VGPU", ID: "LNRO0005", StringID: true,
		Memory: [][2]uint32{{0xfeb10000, 4096}}, LevelIRQs: []uint32{23},
	}).AML()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range [][]byte{
		[]byte("_HID\x0dLNRO0005\x00"),
		{0x86, 9, 0, 1, 0, 0, 0xb1, 0xfe, 0, 0x10, 0, 0},
		{0x89, 6, 0, 1, 1, 23, 0, 0, 0},
	} {
		if !bytes.Contains(data, want) {
			t.Fatalf("AML does not contain %x", want)
		}
	}
}
