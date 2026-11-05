package cc

import (
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/vmm/ramfb"
	"j5.nz/cc/hypervisor"
)

func TestLegacyDisplayApertureRoutingAndCapture(t *testing.T) {
	cpu := &memoryProbeCPU{}
	p := &pc{cpu: cpu, ram: make([]byte, 1<<20), framebuffer: make([]byte, ramfb.Size), vga: newVGA(make([]byte, 32768))}
	p.ram[legacyDisplayAddress-1], p.ram[legacyDisplayAddress+legacyDisplaySize] = 0x56, 0x78
	control := hypervisor.X86Exit{Port: legacyDisplayPort, Size: 4, Count: 1, Write: true, Data: make([]byte, 4)}
	binary.LittleEndian.PutUint32(control.Data, ramfb.Magic)
	if err := p.legacyDisplayIO(control); err != nil {
		t.Fatal(err)
	}
	memory := p.displayMemory()
	for offset, value := range map[int]uint32{4: 1, 8: 801, 12: 603, 16: 102, 20: 2, 24: ramfb.ResizeMagic, 28: 1, 52: 1920, 56: 1080} {
		binary.LittleEndian.PutUint32(memory[offset:], value)
	}
	pixel := uint64(legacyDisplayAddress + ramfb.Pixels)
	if err := p.handleMMIO(hypervisor.X86Exit{Address: pixel, Size: 2, Write: true, Data: []byte{0x80, 0x01}}); err != nil {
		t.Fatal(err)
	}
	if err := p.handleMMIO(hypervisor.X86Exit{Address: pixel, Size: 2}); err != nil {
		t.Fatal(err)
	}
	if cpu.value != 0x0180 || cpu.size != 2 {
		t.Fatal("legacy reads lost guest pixels")
	}
	frame, err := p.capture()
	if err != nil || frame.Bounds().Dx() != 801 || frame.Bounds().Dy() != 603 || frame.RGBAAt(0, 0).R != 255 || frame.RGBAAt(1, 0).R != 0 || frame.RGBAAt(15, 0).R != 255 {
		t.Fatal("legacy capture", frame, err)
	}
	if _, err := ramfb.RequestResize(memory, 1920, 1080); err != nil {
		t.Fatal(err)
	}
	if err := p.legacyDisplayIO(control); err != nil || memory[ramfb.Pixels] != 0x80 {
		t.Fatal("repeated activation cleared pixels", err)
	}
	memory[ramfb.Pixels] = 0
	if frame.RGBAAt(0, 0).R != 255 {
		t.Fatal("capture aliases guest storage")
	}
	if p.ram[legacyDisplayAddress-1] != 0x56 || p.ram[legacyDisplayAddress+legacyDisplaySize] != 0x78 {
		t.Fatal("activation altered neighboring RAM/firmware")
	}
	binary.LittleEndian.PutUint32(control.Data, 0)
	if err := p.legacyDisplayIO(control); err != nil || p.legacyDisplay || len(p.displayMemory()) != ramfb.Size {
		t.Fatal("legacy display did not release VGA aperture", err)
	}
}

func TestLegacyDisplayRejectsMalformedControl(t *testing.T) {
	p := &pc{ram: make([]byte, 1<<20)}
	for _, ex := range []hypervisor.X86Exit{
		{Size: 4, Count: 1, Data: make([]byte, 4)},
		{Size: 1, Count: 1, Write: true, Data: []byte{1}},
		{Size: 4, Count: 2, Write: true, Data: make([]byte, 8)},
		{Size: 4, Count: 1, Write: true, Data: []byte{1, 0, 0, 0}},
	} {
		if err := p.legacyDisplayIO(ex); err == nil || p.legacyDisplay {
			t.Fatal("invalid activation accepted", ex)
		}
	}
}
