package cc

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
	"testing"
)

type nvmeTestCPU struct {
	memoryProbeCPU
	levels map[uint32]bool
}

func (c *nvmeTestCPU) SetIRQ(line uint32, high bool) error { c.levels[line] = high; return nil }

func TestPCINVMeQueuesAndBus(t *testing.T) {
	p, disk := dmaTestPC(t)
	cpu := &nvmeTestCPU{levels: map[uint32]bool{}}
	p.cpu, p.pciIDE = cpu, nil
	p.nvme = newPCINVMe(p)
	config := func(off uint32, write bool, value uint32) uint32 {
		t.Helper()
		p.pciAddress = 0x80000800 | off
		raw := make([]byte, 4)
		binary.LittleEndian.PutUint32(raw, value)
		if err := p.pciIO(hypervisor.X86Exit{Port: 0xcfc, Size: 4, Count: 1, Write: write, Data: raw}); err != nil {
			t.Fatal(err)
		}
		return binary.LittleEndian.Uint32(raw)
	}
	if config(0, false, 0) != 0x00101b36 || config(8, false, 0) != 0x01080200 {
		t.Fatal("wrong NVMe identity")
	}
	config(0x10, true, 0xffffffff)
	if config(0x10, false, 0) != 0xffffc000 {
		t.Fatal("incorrect BAR size")
	}
	const base = 0xd1000000
	config(0x10, true, base)
	if p.nvme.contains(nvmeAddress, 4) || !p.nvme.contains(base, 4) || p.nvme.contains(base+0x3fff, 4) {
		t.Fatal("BAR relocation/bounds")
	}
	if handled, err := p.routeIDE(hypervisor.X86Exit{Port: 0x1f7}); handled || err != nil {
		t.Fatal("IDE still exposed")
	}
	mmio := func(off uint64, value uint64) {
		t.Helper()
		raw := make([]byte, 8)
		binary.LittleEndian.PutUint64(raw, value)
		if err := p.handleMMIO(hypervisor.X86Exit{Address: base + off, Size: 8, Write: true, Data: raw}); err != nil {
			t.Fatal(err)
		}
	}
	mmio(0x24, 15|15<<16)
	mmio(0x28, 0x1000)
	mmio(0x30, 0x2000)
	mmio(0x14, 1)
	command := func(addr int, op byte, cid uint16, prp uint64, dw10, dw11 uint32) {
		b := p.ram[addr : addr+64]
		clear(b)
		b[0] = op
		binary.LittleEndian.PutUint16(b[2:], cid)
		binary.LittleEndian.PutUint32(b[4:], 1)
		binary.LittleEndian.PutUint64(b[24:], prp)
		binary.LittleEndian.PutUint32(b[40:], dw10)
		binary.LittleEndian.PutUint32(b[44:], dw11)
	}
	command(0x1000, 6, 1, 0x5000, 1, 0)
	mmio(0x1000, 1)
	if !bytes.Contains(p.ram[0x5000:0x5100], []byte("cc NVMe Block Device")) || !cpu.levels[16] {
		t.Fatal("identify or admin interrupt")
	}
	// PCI interrupt masking must retain and reassert a pending completion.
	config(4, true, 0x406)
	if cpu.levels[16] {
		t.Fatal("INTx not masked")
	}
	config(4, true, 6)
	if !cpu.levels[16] {
		t.Fatal("pending INTx lost")
	}
	mmio(0x1004, 1)
	if cpu.levels[16] {
		t.Fatal("admin completion not acknowledged")
	}
	command(0x1040, 5, 2, 0x4000, 1|15<<16, 3)
	mmio(0x1000, 2)
	command(0x1080, 1, 3, 0x3000, 1|15<<16, 1|1<<16)
	mmio(0x1000, 3)
	mmio(0x1004, 3)
	command(0x3000, 2, 4, 0x5000, 2, 0)
	mmio(0x1008, 1)
	if !bytes.Equal(p.ram[0x5000:0x5200], disk[1024:1536]) || !cpu.levels[16] {
		t.Fatal("read DMA or I/O interrupt")
	}
	mmio(0x100c, 1)
	if cpu.levels[16] {
		t.Fatal("I/O completion not acknowledged")
	}
	copy(p.ram[0x5000:0x5200], bytes.Repeat([]byte{0xa5}, 512))
	command(0x3040, 1, 5, 0x5000, 2, 0)
	mmio(0x1008, 2)
	result := make([]byte, 512)
	if _, err := p.disk.Device.ReadAt(result, 1024); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, p.ram[0x5000:0x5200]) {
		t.Fatal("write did not reach disk")
	}
	// Reserved memory must not be DMA-accessible, even with a valid backing slice.
	for _, addr := range []uint64{0xa0000, 0xc0000000, ^uint64(0) - 15} {
		if _, err := (nvmeMemory{p}).SliceIPA(addr, 512); err == nil {
			t.Fatalf("DMA accepted %#x", addr)
		}
	}
	path := storageDevicePath(true)
	if len(path) != 34 || !bytes.Equal(path[18:26], []byte{3, 0x17, 16, 0, 1, 0, 0, 0}) {
		t.Fatal("firmware namespace path")
	}
}

func TestNVMeProfileValidation(t *testing.T) {
	p, _ := dmaTestPC(t)
	m := vmm.Machine{Architecture: "x86_64", CPUs: 4, Memory: 16 << 30, Disks: []vmm.Disk{p.disk}}
	m.Disks[0].Bus = "nvme"
	for _, tc := range []struct {
		name     string
		backend  Backend
		rejected bool
	}{
		{"UEFI", Backend{UEFI: true, IDEModel: "synthetic"}, false},
		{"legacy BIOS", Backend{}, true},
		{"IDE conflict", Backend{UEFI: true, PCIIDE: true}, true},
		{"PIO conflict", Backend{UEFI: true, PIOOnly: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rejected := false
			for _, issue := range tc.backend.Validate(m) {
				if issue.Field == "disks[0]" {
					rejected = true
				}
			}
			if rejected != tc.rejected {
				t.Fatalf("disk rejected=%v, want %v", rejected, tc.rejected)
			}
		})
	}
}
