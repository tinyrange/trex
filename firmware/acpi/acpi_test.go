package acpi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestARM64RootAndFixedDescription(t *testing.T) {
	root, err := RootPointer(0x1234567890, "TREXOS")
	if err != nil {
		t.Fatal(err)
	}
	if string(root[:8]) != "RSD PTR " || root[15] != 2 || binary.LittleEndian.Uint64(root[24:]) != 0x1234567890 {
		t.Fatal("invalid RSDP fields")
	}
	for _, data := range [][]byte{root[:20], root} {
		var sum byte
		for _, v := range data {
			sum += v
		}
		if sum != 0 {
			t.Fatal("invalid RSDP checksum")
		}
	}
	fadt, err := ARM64FixedDescription(0x876543210, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(fadt) != 276 || string(fadt[:4]) != "FACP" || fadt[8] != 6 || binary.LittleEndian.Uint32(fadt[112:]) != 1<<20 || binary.LittleEndian.Uint16(fadt[129:]) != 3 || binary.LittleEndian.Uint64(fadt[140:]) != 0x876543210 {
		t.Fatal("invalid ARM64 FADT fields")
	}
	var sum byte
	for _, v := range fadt {
		sum += v
	}
	if sum != 0 {
		t.Fatal("invalid FADT checksum")
	}
	if _, err := ARM64FixedDescription(0, false, true); err == nil {
		t.Fatal("HVC accepted without PSCI")
	}
}

func TestACPICompatibleIDTable(t *testing.T) {
	body, err := CompatibleIDAML(`\_SB.PCI0.FWCF`, "PNPFFFF")
	if err != nil {
		t.Fatal(err)
	}
	table, err := Table("SSDT", body, 2, "TREXOS", "COMPATID", 1, "TREX", 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(table[:4]); got != "SSDT" {
		t.Fatalf("signature = %q, want SSDT", got)
	}
	if got := binary.LittleEndian.Uint32(table[4:8]); got != uint32(len(table)) {
		t.Fatalf("length = %d, want %d", got, len(table))
	}
	var checksum byte
	for _, value := range table {
		checksum += value
	}
	if checksum != 0 {
		t.Fatalf("checksum = %#x, want 0", checksum)
	}
	for _, want := range [][]byte{[]byte("_SB_"), []byte("PCI0"), []byte("FWCF"), []byte("_CID"), {0x0c, 0x41, 0xd0, 0xff, 0xff}} {
		if !bytes.Contains(table, want) {
			t.Errorf("table does not contain %q", want)
		}
	}
}

func TestACPIEISAID(t *testing.T) {
	if got, ok := acpiEISAID("PNP0303"); !ok || got != 0x0303d041 {
		t.Fatalf("acpiEISAID(PNP0303) = %#x, %v", got, ok)
	}
}

func TestACPIRejectsInvalidNames(t *testing.T) {
	for _, test := range []struct{ device, id string }{
		{"PCI0.FWCF", "PNPFFFF"},
		{`\_SB.PCI0.FWCF`, "pnpffff"},
		{`\_SB.PCI0.TOOLONG`, "PNPFFFF"},
	} {
		if _, err := CompatibleIDAML(test.device, test.id); err == nil {
			t.Errorf("CompatibleIDAML(%q, %q) succeeded", test.device, test.id)
		}
	}
}
