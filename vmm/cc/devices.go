package cc

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/vmm/device"
	"github.com/tinyrange/trex/vmm/ramfb"
)

// Keep fixed planar functions reserved even when absent from this profile.
// Experimental placement is caller policy, never an emulator dispatch case.
func reservedPCISlots() map[uint16]bool {
	return map[uint16]bool{0: true, 8: true, 16: true, 24: true, 32: true}
}

func (p *pc) devicePosition() (string, error) {
	r, err := p.cpu.Registers()
	if err != nil {
		return "", err
	}
	s, err := p.cpu.SystemRegisters()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%04x:%x", s.Cs.Selector, r.Rip), nil
}

// Built-in planar IRQs are not wired through the experimental bus. Reject
// collisions rather than letting one source deassert another's interrupt.
func (p *pc) setDeviceIRQ(line uint32, on bool) error {
	reserved := line == 0 || line == 1 || line == 2 || line == 4 || line == 8 || line == 10 || line == 12 || line == 13 || line == 14 || line == 15 || line > 15
	reserved = reserved || line == 9 && (p.acpi != nil || p.nic != nil) || line == 5 && p.sound != nil
	if p.uhci != nil {
		reserved = reserved || line == uint32(p.uhci.config[0x3c])
	}
	if reserved {
		return fmt.Errorf("device: IRQ %d conflicts with the PC platform", line)
	}
	return p.cpu.SetIRQ(line, on)
}
func (p *pc) deviceReservations() []device.Region {
	regions := []device.Region{
		{Space: device.IO, Base: 0, Size: 0x1000}, // planar, BIOS, ISA, CF8/CFC
		{Space: device.Memory, Base: 0, Size: pciMemoryBase},
		{Space: device.Memory, Base: ramfb.Address, Size: ramfb.Size},
		{Space: device.Memory, Base: inputAddress, Size: 0x1000},
		{Space: device.Memory, Base: channelAddress, Size: channelSize},
	}
	if len(p.ram) > pciMemoryBase {
		regions = append(regions, device.Region{Space: device.Memory, Base: highRAMBase, Size: uint64(len(p.ram)) - pciMemoryBase})
	}
	if p.hpet != nil {
		regions = append(regions, device.Region{Space: device.Memory, Base: hpetAddress, Size: 0x400})
	}
	if p.pciIDE != nil && p.pciIDE.config[4]&1 != 0 {
		regions = append(regions, device.Region{Space: device.IO, Base: uint64(p.pciIDE.busMasterBase()), Size: 16})
	}
	if p.uhci != nil && p.uhci.config[4]&1 != 0 {
		regions = append(regions, device.Region{Space: device.IO, Base: uint64(p.uhci.ioBase()), Size: 32})
	}
	if p.pciNIC != nil {
		if p.pciNIC.config[4]&2 != 0 {
			regions = append(regions, device.Region{Space: device.Memory, Base: p.pciNIC.base(), Size: e1000Size})
		}
		if p.pciNIC.config[4]&1 != 0 {
			regions = append(regions, device.Region{Space: device.IO, Base: uint64(binary.LittleEndian.Uint32(p.pciNIC.config[0x14:]) &^ 7), Size: 8})
		}
	}
	return regions
}
