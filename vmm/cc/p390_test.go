package cc

import (
	"bytes"
	"encoding/binary"
	"testing"

	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

// Exercise both host-visible discovery paths: OEMHLP uses PCI BIOS and
// software may use CF8/CFC directly. Neither path requires an ACPI device.
func TestP390DiscoveryAndBARs(t *testing.T) {
	p := &pc{p390: newP390Adapter(), pciAddress: 0x80001810}
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

func TestP390MemoryAndUnsupportedIO(t *testing.T) {
	d := newP390Adapter()
	for _, value := range []byte{0x80, 0, 3} {
		if err := d.io(hypervisor.X86Exit{Port: 0x1c05, Size: 1, Count: 1, Write: true, Data: []byte{value}}); err != nil {
			t.Fatal(err)
		}
	}
	// Writes to microstore retain exact bytes; there is no synthesized
	// processor-ready or mailbox-complete response.
	payload := []byte{0x00, 0x50, 0x22, 0x20}
	if err := d.mmio(hypervisor.X86Exit{Address: 0xd0200000, Size: 4, Write: true, Data: payload}, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.memory[0x200000:0x200004], payload) {
		t.Fatal("microstore changed byte order")
	}
	if d.memory[0x20040] != 0 {
		t.Fatal("fabricated service-processor completion")
	}
	for _, ex := range []hypervisor.X86Exit{
		{Address: 0xd03fffff, Size: 2, Write: true, Data: []byte{1, 2}},
		{Address: 0xd0200000, Size: 4, Write: true, Data: []byte{1}},
		{Address: 0xd0200000, Size: 3, Write: true, Data: []byte{1, 2, 3}},
	} {
		if err := d.mmio(ex, nil); err == nil {
			t.Fatalf("invalid MMIO accepted: %+v", ex)
		}
	}
	d.config[4] = 1
	if d.contains(0xd0200000, 1) {
		t.Fatal("disabled memory decoder")
	}
	if err := d.mmio(hypervisor.X86Exit{Address: 0xd0200000, Size: 1}, nil); err == nil {
		t.Fatal("disabled MMIO accepted")
	}
	for _, ex := range []hypervisor.X86Exit{
		{Port: 0x1c03, Size: 1, Count: 1, Data: []byte{0}},
		{Port: 0x1c04, Size: 1, Count: 1, Write: true, Data: []byte{1}},
		{Port: 0x1c05, Size: 2, Count: 1, Write: true, Data: []byte{1, 2}},
	} {
		if err := d.io(ex); err == nil {
			t.Fatalf("unsupported I/O accepted: %+v", ex)
		}
	}
}

func TestP390PollingTraceIsBounded(t *testing.T) {
	d := newP390Adapter()
	d.record("memory", 0x20043, true, []byte{2})
	for range 10000 {
		d.record("memory", 0x20040, false, []byte{0})
	}
	if len(d.trace) != 2 || d.trace[1].(map[string]any)["count"] != int64(10000) {
		t.Fatal("polling erased request or lost repeat count")
	}
	for i := range 1000 {
		d.record("memory", uint64(i), true, []byte{byte(i)})
	}
	if len(d.trace) != 64 || d.transfers != 11001 {
		t.Fatal("trace exceeded bound or lost transfer count")
	}
}

type p390IRQCPU struct {
	hypervisor.X86
	changes []struct {
		line  uint32
		level bool
	}
}

func (c *p390IRQCPU) SetIRQ(line uint32, level bool) error {
	c.changes = append(c.changes, struct {
		line  uint32
		level bool
	}{line, level})
	return nil
}
func TestP390InterruptMaskAcknowledgmentAndReset(t *testing.T) {
	d := newP390Adapter()
	cpu := &p390IRQCPU{}
	io := func(off uint16, write bool, v byte) byte {
		t.Helper()
		b := []byte{v}
		if err := d.io(hypervisor.X86Exit{Port: uint16(d.ioBase()) + off, Size: 1, Count: 1, Write: write, Data: b}); err != nil {
			t.Fatal(err)
		}
		if err := d.updateIRQ(cpu); err != nil {
			t.Fatal(err)
		}
		return b[0]
	}
	d.service.InterruptPending, d.service.InterruptReason = true, 1
	io(5, true, 0)
	if len(cpu.changes) != 0 || io(7, false, 0) != 2 {
		t.Fatal("masked request either lost or incorrectly delivered")
	}
	io(5, true, 3)
	if len(cpu.changes) != 1 || cpu.changes[0].line != 11 || !cpu.changes[0].level || io(6, false, 0) != 1 {
		t.Fatal("interrupt not delivered on configured PCI line")
	}
	io(4, true, 0xe0)
	if len(cpu.changes) != 2 || cpu.changes[1].level || io(7, false, 0) != 0 {
		t.Fatal("acknowledgment did not deassert")
	}
	d.service.Initialized = true
	io(5, true, 0x80)
	if d.service.Initialized || !d.service.Machine.CPUs[0].Stopped {
		t.Fatal("reset port had no hardware effect")
	}
}
