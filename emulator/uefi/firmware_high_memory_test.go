package uefi

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"io"
	"testing"
)

func TestExternalFirmwareHighMemoryWithPCIHole(t *testing.T) {
	data, err := io.ReadAll(fixture(t, 0xc3))
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint16(data[0x84:], 0x8664)
	// Only firmware's low working set needs backing in this test. Allocation
	// descriptors must still preserve high physical addresses and the PCI hole.
	memory := cpu.NewAddressSpace(32 << 20)
	if err := memory.Map(ramBase, make([]byte, 16<<20), cpu.Read|cpu.Write|cpu.Execute); err != nil {
		t.Fatal(err)
	}
	fw, err := NewFirmware(io.NewSectionReader(bytes.NewReader(data), 0, int64(len(data))), FirmwareOptions{
		Options:      Options{MemoryBase: ramBase, Memory: (17 << 30) - ramBase, Reservations: []MemoryReservation{{Address: 3 << 30, Pages: (1 << 30) / 4096, Type: 0}}},
		Architecture: "amd64", Memory: memory, Gate: func(uint64) []byte { return []byte{0xe6, 0xf6, 0xc3, 0xcc} }, Clock: func() (uint64, uint64) { return 0, 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	m := fw.machine
	if got := m.allocate(2, 2, 1, 3<<30); got != 0 {
		t.Fatalf("allocated PCI hole: %x", got)
	}
	if got := m.allocate(2, 2, 1, 4<<30); got != 4<<30 {
		t.Fatalf("high RAM allocation: %x", got)
	}
	if got := m.allocate(1, 2, 1, ^uint64(0)); got != (17<<30)-4096 {
		t.Fatalf("high RAM truncated: %x", got)
	}
	if m.free(3<<30, 1) {
		t.Fatal("freed reserved PCI hole")
	}
}
