package cc

import (
	"encoding/binary"
	"testing"
)

func TestUHCIKeepsInactiveQueueTail(t *testing.T) {
	u, ram, _ := usbTestController()
	u.ports[0] |= 4
	u.devices[0].configuration = 1
	if err := u.devices[0].key("a", true); err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(ram[0x1000:], 1)
	binary.LittleEndian.PutUint32(ram[0x1004:], 0x2000)
	usbTestTD(ram, 0x2000, 0x2014, 0x69, 0, 1, 8)
	binary.LittleEndian.PutUint32(ram[0x2010:], 1) // Inactive software tail.
	if err := u.schedule(0x1002); err != nil {
		t.Fatal(err)
	}
	if element := binary.LittleEndian.Uint32(ram[0x1004:]); element != 0x2014 {
		t.Fatalf("hardware consumed inactive tail: %#x", element)
	}
	if err := u.schedule(0x1002); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(ram[0x1004:]) != 0x2014 || u.devices[0].reports != 1 {
		t.Fatal("tail changed or report replayed")
	}
}
