package acpi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestLegacyRootIOAperture(t *testing.T) {
	aml, err := (PCIRoot{Legacy: true, MemoryBase: 0xc0000000, MemorySize: 0x3ec00000}).AML()
	if err != nil {
		t.Fatal(err)
	}
	// Decode the resource template, not AML byte patterns: descriptor widths,
	// producer/fixed flags, complete bounds, and port ownership are the contract.
	start := bytes.Index(aml, []byte{0x88, 13, 0, 2, 0x0c, 0})
	if start < 0 {
		t.Fatal("missing bus descriptor")
	}
	var ports [65536]bool
	var ioCount int
	for pos := start; pos < len(aml) && aml[pos] != 0x79; {
		tag := aml[pos]
		if tag&0x80 == 0 || pos+3 > len(aml) {
			t.Fatal("invalid resource descriptor")
		}
		length := int(binary.LittleEndian.Uint16(aml[pos+1:]))
		end := pos + 3 + length
		if end > len(aml) || length < 3 {
			t.Fatal("truncated resource descriptor")
		}
		resource := aml[pos+3 : end]
		if resource[0] == 1 {
			if tag != 0x88 || length != 13 || resource[1] != 0x0c || resource[2] != 3 {
				t.Fatal("I/O must be fixed Word producer")
			}
			gran := binary.LittleEndian.Uint16(resource[3:])
			lo := binary.LittleEndian.Uint16(resource[5:])
			hi := binary.LittleEndian.Uint16(resource[7:])
			translation := binary.LittleEndian.Uint16(resource[9:])
			size := binary.LittleEndian.Uint16(resource[11:])
			if gran != 0 || translation != 0 || uint32(size) != uint32(hi)-uint32(lo)+1 {
				t.Fatal("invalid I/O bounds")
			}
			for p := int(lo); p <= int(hi); p++ {
				if ports[p] {
					t.Fatalf("overlapping port %#x", p)
				}
				ports[p] = true
			}
			ioCount++
		}
		pos = end
	}
	if ioCount != 2 {
		t.Fatalf("got %d I/O windows", ioCount)
	}
	for p, available := range ports {
		reserved := p >= 0xcf8 && p <= 0xcff
		if available == reserved {
			t.Fatalf("incorrect ownership of port %#x", p)
		}
	}
}
