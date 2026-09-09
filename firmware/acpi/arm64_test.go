package acpi

import (
	"encoding/binary"
	"testing"
)

func TestARM64MADTTopology(t *testing.T) {
	data, err := ARM64Interrupts(0x08000000, 0x080a0000, []uint64{0, 0x100}, 23, 25)
	if err != nil {
		t.Fatal(err)
	}
	var sum byte
	for _, b := range data {
		sum += b
	}
	if sum != 0 || string(data[:4]) != "APIC" || int(binary.LittleEndian.Uint32(data[4:])) != len(data) {
		t.Fatal("invalid MADT header/checksum")
	}
	if len(data) != 44+2*80+24+16 {
		t.Fatal("incorrect structure lengths")
	}
	for j := 0; j < 2; j++ {
		gicc := data[44+j*80:]
		if gicc[0] != 11 || gicc[1] != 80 || binary.LittleEndian.Uint32(gicc[8:]) != uint32(j) || binary.LittleEndian.Uint32(gicc[12:]) != 1 || binary.LittleEndian.Uint64(gicc[68:]) != uint64(j)*0x100 || binary.LittleEndian.Uint64(gicc[60:]) != 0 {
			t.Fatal("incorrect GICC topology")
		}
	}
	gicd := data[204:]
	gicr := data[228:]
	if gicd[0] != 12 || gicd[20] != 3 || binary.LittleEndian.Uint64(gicd[8:]) != 0x08000000 || gicr[0] != 14 || binary.LittleEndian.Uint64(gicr[4:]) != 0x080a0000 || binary.LittleEndian.Uint32(gicr[12:]) != 0x40000 {
		t.Fatal("incorrect GIC address ranges")
	}
	if _, err := ARM64Interrupts(0x08000000, 0x080a0000, []uint64{0, 0}, 0, 0); err == nil {
		t.Fatal("duplicate CPU accepted")
	}
}
