package cc

import (
	"bytes"
	"encoding/binary"
	"testing"

	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor/x86state"
)

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
