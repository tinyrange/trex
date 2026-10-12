package cc

import (
	"bytes"
	"encoding/binary"
	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

func pagedBIOSFixture(t *testing.T) (*pc, *biosLegacyCPU, []byte) {
	t.Helper()
	c := &biosLegacyCPU{}
	c.system.Cs.Base = 0xf0000
	c.system.Cr0 = 0x80000011
	c.system.Cr3 = 0x1000
	c.regs = x86state.Registers{Rip: 0x1000 + 0x13*4 + 2, Rsp: 0x2000, Rax: 0x0202, Rcx: 1, Rdx: 0x80, Rbx: 0xff0, Rflags: 0x20002}
	c.system.Es.Base = 0x80000
	disk := make([]byte, 1024)
	for i := range disk {
		disk[i] = byte(i*17 + 3)
	}
	overlay, err := blockstar.NewOverlayDevice(testBlock(t, disk), 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	p := &pc{cpu: c, ram: make([]byte, 1<<20), disk: vmm.Disk{Device: overlay}, biosGeometry: vmm.CHSGeometry{Cylinders: 1, Heads: 1, Sectors: 2}}
	binary.LittleEndian.PutUint32(p.ram[0x1000:], 0x3007)
	for va, pa := range map[uint32]uint32{0x2000: 0x52000, 0x4000: 0x54000, 0x5000: 0x65000, 0x80000: 0x60000, 0x81000: 0x70000} {
		binary.LittleEndian.PutUint32(p.ram[0x3000+va/4096*4:], pa|7)
	}
	binary.LittleEndian.PutUint16(p.ram[0x52004:], 0x0241)
	for i := 0; i < 1024; i++ {
		p.ram[0x80ff0+i] = 0xa5
	}
	return p, c, disk
}
func TestBIOSCHSUsesPagedBufferAndInterruptFrame(t *testing.T) {
	p, c, disk := pagedBIOSFixture(t)
	if err := p.bios(); err != nil {
		t.Fatal(err)
	}
	got, err := p.biosReadContext(0x80ff0, 1024, c.system)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, disk) {
		t.Fatal("BIOS read did not scatter into mapped pages")
	}
	for _, b := range p.ram[0x80ff0:0x813f0] {
		if b != 0xa5 {
			t.Fatal("BIOS wrote unmapped linear-address backing")
		}
	}
	if binary.LittleEndian.Uint16(p.ram[0x52004:]) != 0x0240 || binary.LittleEndian.Uint16(p.ram[0x2004:]) != 0 {
		t.Fatal("BIOS updated physical rather than paged interrupt frame")
	}
	for i := range got {
		got[i] ^= 0xff
	}
	if err := p.biosCopy(0x80ff0, got, true, c.system); err != nil {
		t.Fatal(err)
	}
	c.regs.Rax = 0x0302
	if err := p.bios(); err != nil {
		t.Fatal(err)
	}
	stored := make([]byte, 1024)
	if _, err = p.disk.Device.ReadAt(stored, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, got) {
		t.Fatal("BIOS write did not gather paged buffer")
	}
}
func TestEDDPagedPacketCountCrossesNoncontiguousPages(t *testing.T) {
	p, c, disk := pagedBIOSFixture(t)
	packet := make([]byte, 16)
	packet[0] = 16
	binary.LittleEndian.PutUint16(packet[2:], 2)
	binary.LittleEndian.PutUint16(packet[4:], 0xff0)
	binary.LittleEndian.PutUint16(packet[6:], 0x8000)
	if err := p.biosCopy(0x4ffd, packet, true, c.system); err != nil {
		t.Fatal(err)
	}
	if status := p.extendedDiskTransfer(0x4ffd, false, 0); status != 0 {
		t.Fatalf("EDD status %x", status)
	}
	got, err := p.biosReadContext(0x80ff0, 1024, c.system)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, disk) {
		t.Fatal("EDD buffer uses wrong backing")
	}
	updated, err := p.biosReadContext(0x4ffd, 16, c.system)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint16(updated[2:]) != 2 || p.ram[0x54fff] != 2 || p.ram[0x65000] != 0 {
		t.Fatal("EDD count did not span mapped packet pages")
	}
	if _, err := p.biosReadContext(0x82000, 512, c.system); err == nil {
		t.Fatal("unmapped BIOS buffer accepted")
	}
}
