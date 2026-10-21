package cc

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

func pagedBIOSPC() (*pc, x86state.SystemRegisters) {
	p := &pc{ram: make([]byte, 0x20000)}
	binary.LittleEndian.PutUint32(p.ram[0x1000:], 0x2007)
	for virtual, physical := range map[int]uint32{3: 0x9000, 4: 0x5000, 6: 0x8000} {
		binary.LittleEndian.PutUint32(p.ram[0x2000+virtual*4:], physical|7)
	}
	return p, x86state.SystemRegisters{Cr0: 1 | 1<<31, Cr3: 0x1000}
}
func TestBIOSLinearSpanUsesNoncontiguousPages(t *testing.T) {
	p, s := pagedBIOSPC()
	copy(p.ram[0x9ff8:], []byte("firstpag"))
	copy(p.ram[0x5000:], []byte("secondpage"))
	b, commit, err := p.guestMemory(0x3ff8, 18, s, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "firstpagsecondpage" {
		t.Fatalf("read wrong physical frame: %q", b)
	}
	copy(b, []byte("12345678ABCDEFGHIJ"))
	commit()
	if string(p.ram[0x9ff8:0xa000]) != "12345678" || string(p.ram[0x5000:0x500a]) != "ABCDEFGHIJ" || !bytes.Equal(p.ram[0x3ff8:0x400a], make([]byte, 18)) {
		t.Fatal("writeback used linear address as physical")
	}
	binary.LittleEndian.PutUint32(p.ram[0x2010:], 0)
	if _, _, err = p.guestMemory(0x3ff8, 18, s, true); err == nil {
		t.Fatal("unmapped trailing page accepted")
	}
}
func TestEDDReadsIntoPagedBufferAndUpdatesPagedPacket(t *testing.T) {
	p, s := pagedBIOSPC()
	data := bytes.Repeat([]byte{0x5a}, 1024)
	p.disk = vmm.Disk{Device: testBlock(t, data)}
	packet, commit, err := p.guestMemory(0x3ff8, 16, s, true)
	if err != nil {
		t.Fatal(err)
	}
	packet[0] = 16
	binary.LittleEndian.PutUint16(packet[2:], 1)
	binary.LittleEndian.PutUint16(packet[6:], 0x600)
	commit()
	if status := p.extendedDiskTransfer(0x3ff8, false, 0, s); status != 0 {
		t.Fatalf("EDD status %x", status)
	}
	packet, _, _ = p.guestMemory(0x3ff8, 16, s, true)
	if binary.LittleEndian.Uint16(packet[2:]) != 1 || !bytes.Equal(p.ram[0x8000:0x8200], data[:512]) || p.ram[0x6000] != 0 {
		t.Fatal("EDD did not honor paged packet/buffer addresses")
	}
}
