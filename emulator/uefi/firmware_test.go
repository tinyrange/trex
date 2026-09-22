package uefi

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"testing"

	"github.com/tinyrange/trex/emulator/cpu"
)

func TestExternalFirmwareUsesCallerMemory(t *testing.T) {
	data, err := io.ReadAll(fixture(t, 0x000000c3))
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint16(data[0x84:], 0x8664)
	memory := cpu.NewAddressSpace(16 << 20)
	if err = memory.Map(ramBase, make([]byte, 16<<20), cpu.Read|cpu.Write|cpu.Execute); err != nil {
		t.Fatal(err)
	}
	fw, err := NewFirmware(io.NewSectionReader(bytes.NewReader(data), 0, int64(len(data))), FirmwareOptions{Options: Options{MemoryBase: ramBase, Memory: 16 << 20, TimeUnix: 1704067200}, Architecture: "amd64", Memory: memory, Gate: func(uint64) []byte { return []byte{0xe6, 0xf6, 0xc3, 0xcc} }, Clock: func() (uint64, uint64) { return 2500, 1000 }})
	if err != nil {
		t.Fatal(err)
	}
	entry := fw.Entry()
	for address := range fw.machine.services {
		code := false
		for _, allocation := range fw.machine.allocations {
			if address >= allocation.Base && address < allocation.Base+allocation.Pages*page {
				code = allocation.Type == 5
			}
		}
		if !code {
			t.Fatalf("runtime entrypoint %#x is not EfiRuntimeServicesCode", address)
		}
	}
	if entry.PC != ramBase+0x11000 || entry.Stack <= entry.PC {
		t.Fatalf("entry: %+v", entry)
	}
	var gate [4]byte
	m := fw.machine
	call := func(name string, a [10]uint64) uint64 {
		t.Helper()
		for address, n := range m.services {
			if n == name {
				if err := memory.ReadMemory(address, gate[:], cpu.Execute); err != nil {
					t.Fatal(err)
				}
				if gate != [4]byte{0xe6, 0xf6, 0xc3, 0xcc} {
					t.Fatal(gate)
				}
				status, err := fw.Call(address, a)
				if err != nil {
					t.Fatal(err)
				}
				return status
			}
		}
		t.Fatal("missing", name)
		return 0
	}
	// UINT32 stack arguments do not include the slot's upper bytes.
	guidAddress := entry.Stack - 8192
	identifier := []byte{0xa1, 0x31, 0x1b, 0x5b, 0x62, 0x95, 0xd2, 0x11, 0x8e, 0x3f, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b}
	if err = memory.WriteMemory(guidAddress, identifier); err != nil {
		t.Fatal(err)
	}
	if status := call("OpenProtocol", [10]uint64{entry.ImageHandle, guidAddress, guidAddress + 32, entry.ImageHandle, 0, 0xfffff80100000002}); status != 0 {
		t.Fatalf("UINT32 attributes: %#x", status)
	}
	// Services write directly into the caller's mapping and preserve EFI map keys.
	buffer := entry.Stack - 4096
	if status := call("GetTime", [10]uint64{buffer}); status != 0 {
		t.Fatal(status)
	}
	var date [16]byte
	if err = memory.ReadMemory(buffer, date[:], cpu.Read); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint16(date[:]) != 2024 || date[6] != 2 || binary.LittleEndian.Uint32(date[8:]) != 500000000 {
		t.Fatal(date)
	}
	oldKey := m.mapKey
	if status := call("AllocatePool", [10]uint64{4, 16, buffer}); status != 0 {
		t.Fatal(status)
	}
	if status := call("ExitBootServices", [10]uint64{entry.ImageHandle, oldKey}); status != invalidParameter {
		t.Fatal(status)
	}
	if status := call("ExitBootServices", [10]uint64{entry.ImageHandle, m.mapKey}); status != 0 || !fw.ExitedBootServices() {
		t.Fatal(status)
	}

	descriptor := make([]byte, 40)
	binary.LittleEndian.PutUint32(descriptor, 6)
	binary.LittleEndian.PutUint64(descriptor[8:], ramBase)
	const virtualBase = uint64(0xffff800040000000)
	binary.LittleEndian.PutUint64(descriptor[16:], virtualBase)
	binary.LittleEndian.PutUint64(descriptor[24:], 16)
	binary.LittleEndian.PutUint64(descriptor[32:], uint64(1)<<63|8)
	if err = memory.WriteMemory(buffer, descriptor); err != nil {
		t.Fatal(err)
	}
	if status := call("SetVirtualAddressMap", [10]uint64{40, 40, 1, buffer}); status != 0 {
		t.Fatalf("virtual map: %#x", status)
	}
	runtime := make([]byte, 136)
	if err = memory.ReadMemory(ramBase+0x500, runtime, cpu.Read); err != nil {
		t.Fatal(err)
	}
	pointer := binary.LittleEndian.Uint64(runtime[24:])
	if pointer < virtualBase || pointer >= virtualBase+65536 {
		t.Fatalf("runtime pointer: %#x", pointer)
	}
	checksum := binary.LittleEndian.Uint32(runtime[16:])
	clear(runtime[16:20])
	if crc32.ChecksumIEEE(runtime) != checksum {
		t.Fatal("runtime CRC")
	}
	if status := call("SetVirtualAddressMap", [10]uint64{40, 40, 1, buffer}); status != invalidParameter {
		t.Fatal("accepted second virtual map")
	}
}

func TestMemoryReservationsCannotBeAllocatedOrFreed(t *testing.T) {
	reservation := MemoryReservation{Address: ramBase + 2<<20, Pages: 16, Type: 0}
	m, err := New(fixture(t, 0x14000000), Options{Memory: 16 << 20, Reservations: []MemoryReservation{reservation}})
	if err != nil {
		t.Fatal(err)
	}
	if p := m.allocate(2, 2, 1, reservation.Address); p != 0 {
		t.Fatalf("allocated reserved page %#x", p)
	}
	if m.free(reservation.Address, 1) {
		t.Fatal("freed reserved page")
	}
	if p := m.allocate(1, 2, 1, reservation.Address+4095); p == 0 || p >= reservation.Address {
		t.Fatalf("AllocateMaxAddress crossed reservation: %#x", p)
	}
	found := false
	descriptors := m.descriptors()
	for i := 0; i < len(descriptors); i += 40 {
		d := descriptors[i:]
		if binary.LittleEndian.Uint64(d[8:]) == reservation.Address {
			found = true
			if binary.LittleEndian.Uint32(d) != 0 || binary.LittleEndian.Uint64(d[24:]) != 16 {
				t.Fatal("incorrect reserved descriptor")
			}
		}
	}
	if !found {
		t.Fatal("reservation missing from memory map")
	}
}
