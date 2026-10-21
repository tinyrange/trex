package cc

import (
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

func TestEFIBootstrapHighRAM(t *testing.T) {
	for _, size := range []uint64{2 << 30, 3 << 30, 8 << 30, 16 << 30} {
		p := &pc{ram: make([]byte, 1<<20)}
		end := efiPhysicalEnd(size)
		installEFIBootstrapTables(p.ram, end)
		m := efiMemory{p: p, system: &x86state.SystemRegisters{Cr3: 0x1000, Efer: 1 << 10}}
		for _, addr := range []uint64{0, 0x80000, 0xfee00000, end - 1} {
			got, err := m.physical(addr)
			if err != nil || got != addr {
				t.Fatalf("size=%x addr=%x got=%x err=%v", size, addr, got, err)
			}
		}
		available := end - 0x10000
		for _, r := range efiReservations(size) {
			if r.Address+r.Pages*4096 > end {
				t.Fatal("reservation beyond physical RAM")
			}
			available -= r.Pages * 4096
		}
		if want := size - 0x10000 - 0x80000; available != want {
			t.Fatalf("available=%x want=%x", available, want)
		}
	}
}

func TestUSBKeyboardBootFallback(t *testing.T) {
	p := &pc{keyboard: newKeyboard(func(uint32, bool) error { return nil }), uhci: newUHCI(nil, func(uint32, bool) error { return nil })}
	if err := p.keyEvent("a", true); err != nil {
		t.Fatal(err)
	}
	if len(p.keyboard.queue) == 0 {
		t.Fatal("key lost before USB enumeration")
	}
	p.uhci.devices[0].configuration = 1
	n := len(p.keyboard.queue)
	if err := p.keyEvent("b", true); err != nil {
		t.Fatal(err)
	}
	if len(p.keyboard.queue) != n || len(p.uhci.devices[0].pending) == 0 {
		t.Fatal("configured USB keyboard not used")
	}
}
