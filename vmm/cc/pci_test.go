package cc

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"j5.nz/cc/hypervisor"
)

func TestPCIIDEConfiguration(t *testing.T) {
	p := &pc{acpi: &acpiPM{}, pciIDE: newPCIIDE()}
	io := func(port uint16, width uint8, write bool, value uint32) uint32 {
		t.Helper()
		data := make([]byte, 4)
		binary.LittleEndian.PutUint32(data, value)
		if err := p.handleIO(hypervisor.X86Exit{Port: port, Size: width, Count: 1, Write: write, Data: data[:width]}); err != nil {
			t.Fatal(err)
		}
		return binary.LittleEndian.Uint32(data)
	}
	selectConfig := func(address uint32) { io(0xcf8, 4, true, address) }
	for _, address := range []uint32{0x80000800, 0x80000803} {
		selectConfig(address)
		if got := io(0xcfc, 4, false, 0); got != 0xcc011234 {
			t.Fatalf("identity = %#x", got)
		}
		if io(0xcfc, 2, false, 0) != 0x1234 || io(0xcfe, 2, false, 0) != 0xcc01 || io(0xcff, 1, false, 0) != 0xcc {
			t.Fatal("configuration byte lanes disagree")
		}
	}
	for _, address := range []uint32{0x00000800, 0x80000000, 0x80000900, 0x80010800, 0x80001000} {
		selectConfig(address)
		if got := io(0xcfc, 4, false, 0); got != 0xffffffff {
			t.Fatalf("absent function at %#x = %#x", address, got)
		}
	}
	selectConfig(0x80000808)
	io(0xcfc, 4, true, 0xffffffff)
	if io(0xcfc, 4, false, 0) != 0x01018001 {
		t.Fatal("class, compatibility mode, or revision changed")
	}
	// Compatibility channel BARs and the expansion ROM have no resources.
	for _, offset := range []uint32{0x10, 0x14, 0x18, 0x1c, 0x24, 0x30} {
		selectConfig(0x80000800 | offset)
		io(0xcfc, 4, true, 0xffffffff)
		if io(0xcfc, 4, false, 0) != 0 {
			t.Fatalf("unsupported BAR %#x acquired resources", offset)
		}
	}
	selectConfig(0x80000820)
	io(0xcfc, 4, true, 0xffffffff)
	if io(0xcfc, 4, false, 0) != 0xfffffff1 {
		t.Fatal("bus-master BAR is not 16-byte I/O")
	}
	io(0xcfc, 4, true, 0xc001)
	selectConfig(0x80000804)
	io(0xcfc, 2, true, 0xffff)
	if io(0xcfc, 4, false, 0) != 5 {
		t.Fatal("unsupported command or status bits enabled")
	}
	io(0xcfc, 1, true, 0)
	if io(0x1f7, 1, false, 0) != 0xff {
		t.Fatal("disabled I/O decode still exposed the task file")
	}
	io(0x1f7, 1, true, 0xec) // A disabled command must not reach an ATA device.
	p.ide = &ide{task: [8]byte{7: 0x50}, irq: func(uint32, bool) error { return nil }}
	io(0xcfc, 1, true, 1)
	if io(0x1f7, 1, false, 0) != 0x50 {
		t.Fatal("enabled I/O decode did not expose the task file")
	}
}

func TestPCIIDEHasNoDuplicateACPIDevice(t *testing.T) {
	p := &pc{ram: make([]byte, 1<<20), cpu: &acpiTestCPU{}, now: time.Now, pciIDE: newPCIIDE()}
	if err := p.installACPI(); err != nil {
		t.Fatal(err)
	}
	firmware := p.ram[0xe1000:0xf0000]
	if bytes.Contains(firmware, []byte("IDE0")) || !bytes.Contains(firmware, []byte("PCI0")) {
		t.Fatal("PCI IDE must be enumerated only by the PCI bus")
	}
}
