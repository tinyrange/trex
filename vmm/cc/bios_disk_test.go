package cc

import (
	"bytes"
	"encoding/binary"
	"testing"

	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/vmm"
)

func TestExtendedDiskTransfer(t *testing.T) {
	data := make([]byte, 8*512)
	copy(data[5*512:], bytes.Repeat([]byte{0x5a}, 1024))
	overlay, err := blockstar.NewOverlayDevice(testBlock(t, data), 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	p := &pc{ram: make([]byte, 1<<20), disk: vmm.Disk{Device: overlay}}
	packet := p.ram[0x500:0x510]
	prepare := func(lba uint64, count uint16) {
		clear(packet)
		packet[0] = 16
		binary.LittleEndian.PutUint16(packet[2:], count)
		binary.LittleEndian.PutUint16(packet[4:], 0x20)
		binary.LittleEndian.PutUint16(packet[6:], 0x800)
		binary.LittleEndian.PutUint64(packet[8:], lba)
	}
	prepare(5, 2)
	if status := p.extendedDiskTransfer(0x500, false, 0); status != 0 {
		t.Fatalf("read status %x", status)
	}
	if !bytes.Equal(p.ram[0x8020:0x8420], data[5*512:7*512]) || binary.LittleEndian.Uint16(packet[2:]) != 2 {
		t.Fatal("LBA read or segment:offset buffer mismatch")
	}
	p.ram[0x8020] = 0xa5
	prepare(7, 1)
	if status := p.extendedDiskTransfer(0x500, true, 1); status != 0 {
		t.Fatalf("write status %x", status)
	}
	got := make([]byte, 512)
	if _, err := overlay.ReadAt(got, 7*512); err != nil || got[0] != 0xa5 || data[7*512] != 0 {
		t.Fatal("overlay write mismatch", err)
	}
	for _, tc := range []struct {
		lba   uint64
		count uint16
	}{{7, 2}, {^uint64(0), 1}, {0, 0}, {0, 128}} {
		prepare(tc.lba, tc.count)
		if p.extendedDiskTransfer(0x500, false, 0) == 0 || binary.LittleEndian.Uint16(packet[2:]) != 0 {
			t.Fatalf("invalid packet accepted: %+v", tc)
		}
	}
	prepare(0, 1)
	binary.LittleEndian.PutUint16(packet[6:], 0xffff)
	if p.extendedDiskPosition(0x500, true) != 0 || p.extendedDiskPosition(0x500, false) != 0 {
		t.Fatal("verify/seek incorrectly accessed the transfer buffer")
	}
	if p.extendedDiskTransfer(0x500, false, 0) != 9 {
		t.Fatal("out-of-RAM transfer accepted")
	}
	prepare(0, 1)
	p.disk.ReadOnly = true
	if p.extendedDiskTransfer(0x500, true, 0) != 3 {
		t.Fatal("read-only write accepted")
	}
	if p.extendedDiskTransfer(uint64(len(p.ram)-8), false, 0) != 1 {
		t.Fatal("truncated packet accepted")
	}
	prepare(8, 1)
	if p.extendedDiskPosition(0x500, true) != 4 || p.extendedDiskPosition(0x500, false) != 4 {
		t.Fatal("out-of-range verify/seek accepted")
	}
}

func TestExtendedDiskParameters(t *testing.T) {
	p := &pc{ram: make([]byte, 4096), disk: vmm.Disk{Device: testBlock(t, make([]byte, 8*512))}, biosGeometry: vmm.CHSGeometry{Cylinders: 1, Heads: 2, Sectors: 4}}
	buffer := p.ram[100:140]
	binary.LittleEndian.PutUint16(buffer, 30)
	buffer[26] = 0xaa
	if p.extendedDiskParameters(100) != 0 {
		t.Fatal("parameters failed")
	}
	if binary.LittleEndian.Uint16(buffer) != 26 || binary.LittleEndian.Uint64(buffer[16:]) != 8 || binary.LittleEndian.Uint16(buffer[24:]) != 512 || buffer[26] != 0xaa {
		t.Fatal("parameters or buffer bounds mismatch")
	}
	binary.LittleEndian.PutUint16(buffer, 25)
	if p.extendedDiskParameters(100) != 1 {
		t.Fatal("short buffer accepted")
	}
}

func TestBIOSGeometryTranslation(t *testing.T) {
	for _, tc := range []struct {
		sectors uint64
		heads   int
	}{
		{520 * 16 * 63, 16}, {1024*16*63 + 1, 32}, {(1<<30)/512 + 2048, 64}, {(3<<30)/512 + 2048, 128}, {(16 << 30) / 512, 255},
	} {
		g := translatedGeometry(tc.sectors)
		if g.Heads != tc.heads || g.Cylinders > 1024 || g.Sectors != 63 {
			t.Fatalf("%d sectors: %+v", tc.sectors, g)
		}
	}
}
