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

func TestBIOSDiskPagingAccessedDirty(t *testing.T) {
	p, s := pagedBIOSPC()
	overlay, err := blockstar.NewOverlayDevice(testBlock(t, bytes.Repeat([]byte{0x5a}, 1024)), 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	p.disk = vmm.Disk{Device: overlay}
	// EDD packet straddles two unrelated physical frames; payload is page 6.
	packet := make([]byte, 16)
	packet[0] = 16
	binary.LittleEndian.PutUint16(packet[2:], 1)
	binary.LittleEndian.PutUint16(packet[6:], 0x600)
	copy(p.ram[0x9ff8:], packet[:8])
	copy(p.ram[0x5000:], packet[8:])
	assertEntry := func(address int, want uint32) {
		t.Helper()
		if got := binary.LittleEndian.Uint32(p.ram[address:]); got != want {
			t.Fatalf("entry %#x = %#x, want %#x", address, got, want)
		}
	}
	// Inspection is not an emulated memory access.
	if _, err := p.physical(0x6000, s); err != nil {
		t.Fatal(err)
	}
	assertEntry(0x1000, 0x2007)
	assertEntry(0x2018, 0x8007)
	if status := p.extendedDiskTransfer(0x3ff8, false, 0, s); status != 0 {
		t.Fatal(status)
	}
	assertEntry(0x1000, 0x2027) // directory accessed, NOT dirty
	assertEntry(0x200c, 0x9067) // packet updated on both pages
	assertEntry(0x2010, 0x5067)
	assertEntry(0x2018, 0x8067) // BIOS-loaded code/data must survive paging
	if !bytes.Equal(p.ram[0x8000:0x8200], bytes.Repeat([]byte{0x5a}, 512)) {
		t.Fatal("disk data missing")
	}
	binary.LittleEndian.PutUint32(p.ram[0x2018:], 0x8007)
	if status := p.extendedDiskTransfer(0x3ff8, true, 0, s); status != 0 {
		t.Fatal(status)
	}
	assertEntry(0x2018, 0x8027) // writing disk only READS guest payload
}

func TestBIOSPagingLargePageAndRejectedSpan(t *testing.T) {
	p, s := pagedBIOSPC()
	// A validated read marks Accessed, never Dirty, even on commit.
	_, commit, err := p.guestMemory(0x6000, 1, s, false)
	if err != nil {
		t.Fatal(err)
	}
	commit()
	if got := binary.LittleEndian.Uint32(p.ram[0x2018:]); got != 0x8027 {
		t.Fatalf("read PTE %#x", got)
	}
	// A missing trailing page must neither expose a partial write buffer nor
	// change the first page's metadata.
	binary.LittleEndian.PutUint32(p.ram[0x200c:], 0x9007)
	binary.LittleEndian.PutUint32(p.ram[0x2010:], 0)
	if _, _, err := p.guestMemory(0x3ff8, 16, s, true); err == nil {
		t.Fatal("accepted unmapped tail")
	}
	if got := binary.LittleEndian.Uint32(p.ram[0x200c:]); got != 0x9007 {
		t.Fatalf("rejected PTE %#x", got)
	}
	// With PSE the PDE itself is the leaf, so only it receives Dirty.
	p.ram = make([]byte, 4<<20)
	binary.LittleEndian.PutUint32(p.ram[0x1000:], 0x87)
	s = x86state.SystemRegisters{Cr0: 1 | 1<<31, Cr3: 0x1000, Cr4: 1 << 4}
	b, commit, err := p.guestMemory(0x3ff8, 16, s, true)
	if err != nil {
		t.Fatal(err)
	}
	copy(b, []byte("dirty large page"))
	commit()
	if got := binary.LittleEndian.Uint32(p.ram[0x1000:]); got != 0xe7 {
		t.Fatalf("large PDE %#x", got)
	}
}
