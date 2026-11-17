package cc

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/s390"
	"github.com/tinyrange/trex/vmm/device"
	"testing"
	"time"

	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

// Exercise both host-visible discovery paths: OEMHLP uses PCI BIOS and
// software may use CF8/CFC directly. Neither path requires an ACPI device.
func TestP390DiscoveryAndBARs(t *testing.T) {
	p := &pc{pciAddress: 0x80001810}
	if err := p.devices.Attach([]device.Spec{s390.P390Device("p390", 5<<3, false, time.Time{})}, device.Profile{Architecture: "i386", CPUs: 1}, reservedPCISlots()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.devices.Close() })
	r := x86state.Registers{Rax: 0xb102, Rcx: 0x36, Rdx: 0x1014}
	status, err := p.pciBIOS(&r)
	if err != nil || status != 0 || r.Rbx != 0x28 || p.pciAddress != 0x80001810 {
		t.Fatalf("discovery: %x %+v %v", status, r, err)
	}
	config := func(off uint16, size uint8, write bool, value uint32) uint32 {
		t.Helper()
		v, e := p.pciBIOSConfig(0x28, off, size, write, value)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	if got := config(0x2c, 4, false, 0); got != 0x00591014 {
		t.Fatalf("subsystem=%x", got)
	}
	for _, tc := range []struct {
		off        uint16
		mask, base uint32
	}{
		{0x10, 0xffffffe1, 0x2c01}, {0x14, 0xffc00000, 0xd0400000},
	} {
		config(tc.off, 4, true, 0xffffffff)
		if got := config(tc.off, 4, false, 0); got != tc.mask {
			t.Fatalf("BAR %x mask=%x", tc.off, got)
		}
		config(tc.off, 4, true, tc.base)
		if got := config(tc.off, 4, false, 0); got != tc.base {
			t.Fatalf("BAR %x relocation=%x", tc.off, got)
		}
	}
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, 0x80002800)
	if err := p.handleIO(hypervisor.X86Exit{Port: 0xcf8, Size: 4, Count: 1, Write: true, Data: data}); err != nil {
		t.Fatal(err)
	}
	if err := p.handleIO(hypervisor.X86Exit{Port: 0xcfc, Size: 4, Count: 1, Data: data}); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(data); got != 0x00361014 {
		t.Fatalf("CF8 identity=%x", got)
	}
	config(0, 4, true, 0xffffffff)
	if got := config(0, 4, false, 0); got != 0x00361014 {
		t.Fatalf("read-only identity=%x", got)
	}
}
