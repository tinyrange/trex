package acpi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestARM64PlatformTables(t *testing.T) {
	timer, err := ARM64GenericTimer(30, 27)
	if err != nil {
		t.Fatal(err)
	}
	ecam, err := PCIConfiguration(0x20000000, 0, 0, 15)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range [][]byte{timer, ecam} {
		var sum byte
		for _, b := range table {
			sum += b
		}
		if sum != 0 || int(binary.LittleEndian.Uint32(table[4:])) != len(table) {
			t.Fatal("invalid ACPI header/checksum")
		}
	}
	if binary.LittleEndian.Uint32(timer[56:]) != 30 || binary.LittleEndian.Uint32(timer[64:]) != 27 {
		t.Fatal("timer interrupt offsets")
	}
	if binary.LittleEndian.Uint64(ecam[44:]) != 0x20000000 || ecam[55] != 15 {
		t.Fatal("ECAM allocation offsets")
	}
	aml, err := (PCIRoot{LastBus: 15, MemoryBase: 0x21000000, MemorySize: 0x1000000, Interrupts: []PCIInterrupt{{1, 0, 78}}}).AML()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"PCI0", "_HID", "_CID", "_CRS", "_PRT", "_CCA"} {
		if !bytes.Contains(aml, []byte(name)) {
			t.Fatalf("missing %s", name)
		}
	}
	if _, err := ARM64GenericTimer(30, 30); err == nil {
		t.Fatal("accepted overlapping PPIs")
	}
	if _, err := PCIConfiguration(1, 0, 0, 15); err == nil {
		t.Fatal("accepted misaligned ECAM")
	}
	if _, err := (PCIRoot{MemorySize: 1, Interrupts: []PCIInterrupt{{1, 4, 78}}}).AML(); err == nil {
		t.Fatal("accepted invalid INTx pin")
	}
}
