package uefi

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/tinyrange/trex/emulator/cpu"
	"github.com/tinyrange/trex/windows/guid"
)

func externalFirmware(t *testing.T) (*Firmware, []byte) {
	t.Helper()
	data, err := io.ReadAll(fixture(t, 0x000000c3))
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint16(data[0x84:], 0x8664)
	memory := cpu.NewAddressSpace(16 << 20)
	if err := memory.Map(ramBase, make([]byte, 16<<20), cpu.Read|cpu.Write|cpu.Execute); err != nil {
		t.Fatal(err)
	}
	fw, err := NewFirmware(io.NewSectionReader(bytes.NewReader(data), 0, int64(len(data))), FirmwareOptions{
		Options: Options{MemoryBase: ramBase, Memory: 16 << 20}, Memory: memory, Architecture: "amd64",
		Gate: func(uint64) []byte { return []byte{0xe6, 0xf6, 0xc3, 0xcc} }, Clock: func() (uint64, uint64) { return 0, 1000 },
	})
	if err != nil {
		t.Fatal(err)
	}
	return fw, data
}

func callExternal(t *testing.T, fw *Firmware, name string, args [10]uint64) uint64 {
	t.Helper()
	for address, service := range fw.machine.services {
		if service == name {
			status, err := fw.Call(address, args)
			if err != nil {
				t.Fatal(err)
			}
			return status
		}
	}
	t.Fatalf("no %s service", name)
	return 0
}

func TestLoadPositionIndependentEFIImage(t *testing.T) {
	fw, data := externalFirmware(t)
	// Strip the fixture's base relocation directory without setting COFF's
	// fixed-address bit, as in the Linux EFI stub.
	clear(data[0x98+112+5*8 : 0x98+112+6*8])
	m := fw.machine
	base := fw.Entry().Stack - (64 << 10)
	path := base + 32
	src := base + 256
	m.put(path, []byte{1, 1, 4, 0, 0x7f, 0xff, 4, 0})
	m.put(src, data)
	parent := fw.Entry().ImageHandle
	if status := callExternal(t, fw, "LoadImage", [10]uint64{0, parent, path, src, uint64(len(data)), base}); status != 0 {
		t.Fatalf("load status %#x", status)
	}
	handle := m.read64(base)
	loaded := m.protocols[handle][loadedImageGUID]
	if loaded == 0 || m.read64(loaded+8) != parent || m.read64(loaded+32) == path {
		t.Fatal("loaded image interface lacks parent or independent path")
	}
	child, status := fw.StartImage(handle)
	if status != 0 || child.PC != m.read64(loaded+64)+0x1000 || child.ImageHandle != handle {
		t.Fatalf("start: %+v, status %#x", child, status)
	}
	if status := callExternal(t, fw, "UnloadImage", [10]uint64{handle}); status != invalidParameter {
		t.Fatalf("unloaded a running image: %#x", status)
	}
	if status := callExternal(t, fw, "ExitBootServices", [10]uint64{parent, m.mapKey}); status != invalidParameter {
		t.Fatalf("inactive parent exited boot services: %#x", status)
	}
	fw.FinishImage(handle, parent)
	if status := callExternal(t, fw, "UnloadImage", [10]uint64{handle}); status != 0 || m.protocols[handle] != nil {
		t.Fatalf("unload status %#x", status)
	}
}

func TestLocateRegisteredInitrdDevicePath(t *testing.T) {
	fw, _ := externalFirmware(t)
	m := fw.machine
	extraID, _ := guid.Parse("{4006C0C1-FCB3-403E-996D-4A6C8724E06D}")
	pathID, _ := guid.Parse(devicePathGUID)
	out := fw.Entry().Stack - 4096
	efiPath := []byte{4, 3, 8, 0, 0, 0, 0, 0, 0x7f, 0xff, 4, 0}
	m.put(out+16, pathID[:])
	m.put(out+32, extraID[:])
	m.put(out+48, efiPath)
	m.put(out+64, efiPath)
	m.u64(out+80, out+64)
	args := [10]uint64{out, out + 16, out + 48, out + 32, out + 100}
	if status := callExternal(t, fw, "InstallMultipleProtocolInterfaces", args); status != 0 {
		t.Fatalf("install status %#x", status)
	}
	handle := m.read64(out)
	if status := callExternal(t, fw, "LocateDevicePath", [10]uint64{out + 32, out + 80, out + 88}); status != 0 || m.read64(out+80) != out+72 || m.read64(out+88) != handle {
		t.Fatalf("locate status %#x", status)
	}
	args[0] = handle
	if status := callExternal(t, fw, "UninstallMultipleProtocolInterfaces", args); status != 0 || m.protocols[handle] != nil {
		t.Fatalf("uninstall status %#x", status)
	}
}
