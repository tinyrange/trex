package r3000

import (
	"encoding/binary"
	"testing"
)

func TestIP24VirtualDMABlitsAcrossPageBoundary(t *testing.T) {
	m, err := newIP24(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	const (
		table   = ip24RAMBase + 0x10000
		virtual = 0x04001ffc
		first   = ip24RAMBase + 0x12000
		second  = ip24RAMBase + 0x15000
	)
	write := func(address, value uint32) {
		t.Helper()
		if !m.write64(uint64(address), 4, uint64(value)) {
			t.Fatalf("unmapped DMA setup store at %#x", address)
		}
	}
	binary.BigEndian.PutUint32(m.ram[0x10004:], first>>6|2)
	binary.BigEndian.PutUint32(m.ram[0x10008:], second>>6|2)
	binary.BigEndian.PutUint32(m.ram[0x12ffc:], 0x918278)
	binary.BigEndian.PutUint32(m.ram[0x15000:], 0x463aad)

	write(newportBase+0, 0x30008799) // Source op, packed 32-bit host pixels.
	write(newportBase+4, 0xc6)       // Packed host block without explicit X/Y stops.
	write(newportBase+0x150, 19<<16|18)
	write(newportBase+0x154, 20<<16|18)
	write(ip24MC+0x16c, mcDMAXlate|mcDMAIRQ)
	write(ip24MC+0x184, 0x04000000)
	write(ip24MC+0x18c, table>>6|2)
	write(ip24MC+0x2004, virtual)
	write(ip24MC+0x2014, 1<<16|8)
	write(ip24MC+0x201c, 1<<16)
	write(ip24MC+0x2034, 0x10)
	write(ip24MC+0x202c, newportBase+0xa30)
	if run, _ := m.read64(ip24MC+0x204c, 4); run != mcDMARunning {
		t.Fatalf("DMA did not start: run=%#x", run)
	}
	m.cycles += 1000
	m.updateInterrupts()
	for x, want := range map[int]uint32{19: 0x918278, 20: 0x463aad} {
		if got := m.newport.rgb[18*newportStride+x]; got != want {
			t.Errorf("Newport pixel %d = %#x, want %#x", x, got, want)
		}
	}
	if run, _ := m.read64(ip24MC+0x204c, 4); run != mcDMAComplete || m.int3.reg[0]&0x10 == 0 {
		t.Fatalf("DMA completion state run=%#x local0=%#x", run, m.int3.reg[0])
	}
	write(ip24MC+0x164, 0)
	m.updateInterrupts()
	if m.int3.reg[0]&0x10 != 0 {
		t.Fatal("DMA interrupt remained asserted after acknowledging its cause")
	}
}
