package cc

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/boot/darwin"
)

func TestAppleUtilityPCINVRAMBank(t *testing.T) {
	const (
		config   = uint64(0x40010000)
		bar      = uint64(0x50010000)
		bankAt   = uint64(0xa00000)
		bankSize = 8192
	)
	d := newProtocolTestBus(func(string, any) {})
	d.ramBase, d.ram = 0x70000000, make([]byte, 0x4000)
	if err := d.util.init(); err != nil {
		t.Fatal(err)
	}
	defer d.util.store.Close()
	d.pciUtil = newAppleStoragePCI(0x40010000, 0x50010000, 2, d.util.store, d.dmaMemory, nil)
	read := func(a uint64, size int) uint64 {
		t.Helper()
		v, err := d.Read(a, size)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	write := func(a uint64, size int, v uint64) {
		t.Helper()
		if err := d.Write(a, size, v); err != nil {
			t.Fatal(err)
		}
	}
	if got := read(config, 4); got != 0x1a00106b {
		t.Fatalf("Apple utility PCI identity = %#x", got)
	}
	if got := read(config+0x2c, 4); got != 0x0002106b {
		t.Fatalf("Apple utility subsystem identity = %#x", got)
	}
	// Walk the capability list like the original transport: Apple data is
	// inline in a vendor capability, distinct from the BAR device config.
	found := false
	seen := make(map[uint64]bool)
	for cap := read(config+0x34, 1); cap != 0; cap = read(config+cap+1, 1) {
		if cap < 0x40 || cap > 0xfc || seen[cap] {
			t.Fatalf("invalid capability chain at %#x", cap)
		}
		seen[cap] = true
		if read(config+cap, 1) != 9 || read(config+cap+3, 1) != 9 {
			continue
		}
		if read(config+cap+2, 1) != 14 || read(config+cap+4, 2) != 0x106b {
			t.Fatal("invalid Apple vendor capability")
		}
		for i := uint64(0); i < 8; i++ {
			if got := read(config+cap+6+i, 1); got != 0 {
				t.Fatalf("legacy Apple storage feature byte %d = %#x", i, got)
			}
			write(config+cap+6+i, 1, 0) // negotiated legacy features
		}
		found = true
	}
	if !found {
		t.Fatal("Apple vendor capability missing from PCI chain")
	}
	write(config+4, 2, 6)
	if got := read(bar+0x213c, 1); got != 2 {
		t.Fatalf("device role = %d, want utility storage", got)
	}
	if got := read(bar+0x2100, 8); got != (32<<20)/512 {
		t.Fatalf("utility capacity = %d sectors", got)
	}
	if got := read(bar+4, 4); got != 1<<6 {
		t.Fatalf("utility block features = %#x, want writable BLK_SIZE", got)
	}
	write(bar+20, 1, 3)
	write(bar+8, 4, 0)
	write(bar+12, 4, 1<<6)
	write(bar+8, 4, 1)
	write(bar+12, 4, 1)
	write(bar+20, 1, 11)
	if read(bar+20, 1)&8 == 0 {
		t.Fatal("ordinary block features rejected")
	}
	write(bar+24, 2, 8)
	write(bar+32, 8, d.ramBase)
	write(bar+40, 8, d.ramBase+0x100)
	write(bar+48, 8, d.ramBase+0x200)
	write(bar+28, 2, 1)
	write(bar+20, 1, 15)

	var submitted uint16
	request := func(kind uint32) {
		t.Helper()
		flags := uint16(3)
		if kind == 1 {
			flags = 1
		}
		// A full NVRAM bank may span multiple DMA descriptors. Its request
		// sector already contains the offset from /product/util/regions.
		for i, part := range []struct {
			offset, size uint32
			flags, next  uint16
		}{{0x300, 16, 1, 1}, {0x1000, 4096, flags, 2}, {0x2000, 4096, flags, 3}, {0x3f0, 1, 2, 0}} {
			p := d.ram[i*16:]
			binary.LittleEndian.PutUint64(p, d.ramBase+uint64(part.offset))
			binary.LittleEndian.PutUint32(p[8:], part.size)
			binary.LittleEndian.PutUint16(p[12:], part.flags)
			binary.LittleEndian.PutUint16(p[14:], part.next)
		}
		binary.LittleEndian.PutUint32(d.ram[0x300:], kind)
		binary.LittleEndian.PutUint64(d.ram[0x308:], bankAt/512)
		d.ram[0x3f0] = 0xff
		submitted++
		binary.LittleEndian.PutUint16(d.ram[0x102:], submitted)
		write(bar+0x1000, 2, 0)
		if d.ram[0x3f0] != 0 || binary.LittleEndian.Uint16(d.ram[0x202:]) != submitted {
			t.Fatalf("request %d: status=%d used=%d", submitted, d.ram[0x3f0], binary.LittleEndian.Uint16(d.ram[0x202:]))
		}
		wantUsed := uint32(1)
		if kind == 0 {
			wantUsed += bankSize
		}
		used := d.ram[0x204+int(submitted-1)*8:]
		if binary.LittleEndian.Uint32(used) != 0 || binary.LittleEndian.Uint32(used[4:]) != wantUsed {
			t.Fatalf("request %d: wrong used descriptor/length", submitted)
		}
	}

	request(0)
	want, err := darwin.EmptyARM64NVRAM(bankSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.ram[0x1000:0x3000], want) {
		t.Fatal("initial PCI read differs from native handoff NVRAM bank")
	}
	changed := make([]byte, bankSize)
	for i := range changed {
		changed[i] = byte(i ^ i>>8)
	}
	copy(d.ram[0x1000:0x3000], changed)
	request(1)

	// Firmware disk Unit 1 occupies the legacy aperture. Disabling that
	// aperture must leave the shared NVRAM backing available through PCI.
	d.util.device = nil

	clear(d.ram[0x1000:0x3000])
	request(0)
	if !bytes.Equal(d.ram[0x1000:0x3000], changed) {
		t.Fatal("full-bank write lost after disabling legacy utility MMIO")
	}
	backing := make([]byte, bankSize)
	if n, err := d.util.store.ReadAt(backing, int64(bankAt)); err != nil || n != len(backing) || !bytes.Equal(backing, changed) {
		t.Fatalf("PCI writes did not reach shared utility backing: n=%d err=%v", n, err)
	}
}
