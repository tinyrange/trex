package cc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
)

func dmaTestPC(t *testing.T) (*pc, []byte) {
	t.Helper()
	data := make([]byte, 256<<10)
	for i := range data {
		data[i] = byte(i*7 + i/512)
	}
	overlay, err := blockstar.NewOverlayDevice(testBlock(t, data), int64(len(data)), 4096)
	if err != nil {
		t.Fatal(err)
	}
	p := &pc{ram: make([]byte, 1<<20), pciIDE: newPCIIDE(), disk: vmm.Disk{Device: overlay}}
	p.ide = newIDE(p.disk, vmm.CHSGeometry{Cylinders: 8, Heads: 2, Sectors: 32}, func(uint32, bool) error { return nil })
	p.ide.dmaEnabled = true
	p.pciIDE.config[4] = 5
	binary.LittleEndian.PutUint32(p.pciIDE.bm[4:], 0x1000)
	return p, data
}

func dmaPRD(p *pc, index int, address uint32, size uint16, last bool) {
	prd := p.ram[0x1000+index*8 : 0x1008+index*8]
	binary.LittleEndian.PutUint32(prd, address)
	binary.LittleEndian.PutUint16(prd[4:], size)
	if last {
		prd[7] = 0x80
	}
}

func dmaCommand(t *testing.T, p *pc, write bool, count byte) {
	t.Helper()
	p.ide.task[2], p.ide.task[3], p.ide.task[4], p.ide.task[5], p.ide.task[6] = count, 2, 0, 0, 0xe0
	cmd := byte(0xc8)
	if write {
		cmd = 0xca
	}
	if err := p.ideIO(hypervisor.X86Exit{Port: 0x1f7, Size: 1, Count: 1, Write: true, Data: []byte{cmd}}); err != nil {
		t.Fatal(err)
	}
}

func dmaStart(t *testing.T, p *pc, write bool) {
	t.Helper()
	command := byte(9)
	if write {
		command = 1
	}
	if err := p.busMasterIO(hypervisor.X86Exit{Port: 0xc000, Size: 1, Count: 1, Write: true, Data: []byte{command}}); err != nil {
		t.Fatal(err)
	}
}

func TestIDEPhysicalRegionTransfers(t *testing.T) {
	for _, write := range []bool{false, true} {
		for _, startFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("write%t_startFirst%t", write, startFirst), func(t *testing.T) {
				p, data := dmaTestPC(t)
				dmaPRD(p, 0, 0x2ff00, 256, false)
				dmaPRD(p, 1, 0x40020, 768, true)
				payload := bytes.Repeat([]byte{0xa5}, 1024)
				if write {
					copy(p.ram[0x2ff00:], payload[:256])
					copy(p.ram[0x40020:], payload[256:])
				}
				if startFirst {
					dmaStart(t, p, write)
				}
				dmaCommand(t, p, write, 2)
				if !startFirst {
					dmaStart(t, p, write)
				}
				if p.pciIDE.bm[2]&7 != 4 || !p.ide.pending || p.ide.status() != 0x50 || p.ide.remaining != 0 || p.ide.lba != 4 {
					t.Fatalf("completion: BM=%x ATA=%x remaining=%d LBA=%d", p.pciIDE.bm[2], p.ide.status(), p.ide.remaining, p.ide.lba)
				}
				if write {
					got := make([]byte, 1024)
					if _, err := p.disk.Device.ReadAt(got, 1024); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, payload) || data[1024] == 0xa5 {
						t.Fatal("DMA write did not update only the disk overlay")
					}
				} else if !bytes.Equal(p.ram[0x2ff00:0x30000], data[1024:1280]) || !bytes.Equal(p.ram[0x40020:0x40320], data[1280:2048]) {
					t.Fatal("scatter DMA read mismatch")
				}
				for _, a := range []int{0x2feff, 0x30000, 0x4001f, 0x40320} {
					if p.ram[a] != 0 {
						t.Fatal("DMA overwrote a guard byte")
					}
				}
				if err := p.busMasterIO(hypervisor.X86Exit{Port: 0xc002, Size: 1, Count: 1, Write: true, Data: []byte{0x64}}); err != nil {
					t.Fatal(err)
				}
				if p.pciIDE.bm[2] != 0x60 {
					t.Fatal("bus-master status W1C or capability bits incorrect")
				}
			})
		}
	}
}

func TestIDEZeroRegionCountAndBusMasterEnable(t *testing.T) {
	p, data := dmaTestPC(t)
	dmaPRD(p, 0, 0x20000, 0, true)
	p.pciIDE.config[4] = 1
	dmaCommand(t, p, false, 128)
	dmaStart(t, p, false)
	if !p.ide.dmaPending || p.ram[0x20000] != 0 || p.ide.pending {
		t.Fatal("disabled bus mastering accessed memory or completed")
	}
	p.pciIDE.config[4] = 5
	if err := p.tryIDEDMA(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.ram[0x20000:0x30000], data[1024:1024+65536]) {
		t.Fatal("zero descriptor count must transfer 64 KiB")
	}
}

func TestIDEDMARejectsInvalidRegions(t *testing.T) {
	for _, kind := range []string{"short_table", "outside_ram", "cross_64k", "bad_table_address", "wrong_direction"} {
		t.Run(kind, func(t *testing.T) {
			p, _ := dmaTestPC(t)
			dmaPRD(p, 0, 0x20000, 512, true)
			switch kind {
			case "short_table":
				dmaPRD(p, 0, 0x20000, 256, true)
			case "outside_ram":
				dmaPRD(p, 0, uint32(len(p.ram)), 512, true)
			case "cross_64k":
				dmaPRD(p, 0, 0x2ff00, 512, true)
			case "bad_table_address":
				binary.LittleEndian.PutUint32(p.pciIDE.bm[4:], uint32(len(p.ram)))
			}
			before := append([]byte(nil), p.ram...)
			dmaCommand(t, p, false, 1)
			dmaStart(t, p, kind == "wrong_direction")
			if p.pciIDE.bm[2]&7 != 6 || p.ide.status()&1 == 0 || p.ide.dmaPending || !bytes.Equal(p.ram, before) {
				t.Fatal("invalid DMA did not fail before changing guest memory")
			}
		})
	}
}
