// Package cc implements an in-process PC backend using CrumbleCracker.
package cc

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/vmm/ramfb"
	"runtime"
	"time"

	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
)

// Low RAM stops before PCI MMIO; additional RAM starts above the 32-bit
// device window. Host backing remains compact across the physical hole.
const pciMemoryBase = 0xc0000000
const highRAMBase = 1 << 32

type Backend struct {
	ACPI, PCIIDE, HPET, UEFI bool
	// PIOOnly disables the PCI IDE disk's DMA capability.
	PIOOnly bool
	// IDEModel selects synthetic (default) or the native ich7-pata profile.
	IDEModel string
	// OverlayLimit bounds dirty snapshot memory; zero uses 256 MiB.
	OverlayLimit int64
}

func Available() bool { return runtime.GOOS == "linux" && runtime.GOARCH == "amd64" }
func Capabilities() []string {
	return []string{"boot.darwin", "disk", "disk.bus.ide", "disk.snapshot", "disk.geometry.chs", "display.capturable", "screenshot", "input.key", "input.pointer", "lifecycle.pause", "lifecycle.stop", "extension.cc.v1", "network.ethernet", "channel.shared-memory"}
}
func (*Backend) ID() string             { return "cc.v1" }
func (*Backend) Capabilities() []string { return Capabilities() }
func (b *Backend) Validate(m vmm.Machine) []vmm.ValidationIssue {
	var issues []vmm.ValidationIssue
	add := func(field, message string) {
		issues = append(issues, vmm.ValidationIssue{Code: "cc.unsupported", Field: field, Message: message, Backend: b.ID()})
	}
	if b.IDEModel != "" && b.IDEModel != "synthetic" && b.IDEModel != "ich7-pata" {
		add("ide_model", "IDE model must be synthetic or ich7-pata")
	}
	if b.IDEModel == "ich7-pata" && !b.PCIIDE && !b.UEFI {
		add("ide_model", "ich7-pata requires PCI IDE")
	}
	if m.Boot != nil {
		add("boot", "cc does not support Linux direct boot")
	}
	if m.DarwinBoot != nil {
		if len(m.Networks) != 0 {
			add("networks", "Darwin SMC and NE2000 require distinct I/O resources; networking is not supported in this profile")
		}
		if b.UEFI || m.Architecture != "x86_64" {
			add("boot", "Darwin direct boot requires x86_64 without UEFI image execution")
		}
		if err := m.DarwinBoot.Validate(); err != nil {
			add("boot", err.Error())
		}
	}
	if b.UEFI && m.Architecture != "x86_64" {
		add("architecture", "cc UEFI requires x86_64")
	}
	if b.OverlayLimit < 0 {
		add("overlay_limit", "snapshot overlay limit must be positive")
	}
	if !Available() {
		add("backend", "cc PC execution requires Linux/amd64 KVM")
	}
	if m.Architecture != "i386" && m.Architecture != "x86_64" {
		add("architecture", "cc PC supports i386 and x86_64")
	}
	if m.CPUs != 1 {
		add("cpus", "cc PC requires one CPU")
	}
	maxMemory := int64(pciMemoryBase)
	if m.Architecture == "x86_64" {
		maxMemory = 8 << 30
	}
	if b.UEFI {
		maxMemory = 2 << 30 // Keep the native UEFI execution profile unchanged.
	}
	if m.Memory < 16<<20 || m.Memory > maxMemory || m.Memory%4096 != 0 {
		add("memory", fmt.Sprintf("memory must be page-aligned and between 16 MiB and %d GiB", maxMemory>>30))
	}
	if len(m.Disks) != 1 {
		add("disks", "cc PC requires one primary IDE disk")
	}
	for i, d := range m.Disks {
		field := fmt.Sprintf("disks[%d]", i)
		if d.Device == nil {
			add(field, "disk device is required")
			continue
		}
		if d.Bus != "" && d.Bus != "auto" && d.Bus != "ide" || d.Unit != 0 || d.Media != "" && d.Media != "disk" {
			add(field, "disk must be primary IDE master with disk media")
		}
		g := d.Device.Geometry()
		if g.LogicalBlockSize != 512 || g.Size < 512 || g.Size%512 != 0 {
			add(field, "disk requires complete 512-byte sectors")
		}
		if d.CHS != nil {
			c := d.CHS
			if c.Cylinders < 1 || c.Cylinders > 1024 || c.Heads < 1 || c.Heads > 16 || c.Sectors < 1 || c.Sectors > 63 || int64(c.Cylinders*c.Heads*c.Sectors)*512 > g.Size {
				add(field+".chs", "invalid legacy ATA geometry")
			}
		}
		if !d.ReadOnly && !d.Snapshot && !d.Device.Capabilities().Writable {
			add(field, "writable disk or snapshot overlay is required")
		}
	}
	if len(m.Networks) > 1 {
		add("networks", "cc PC supports one ISA NE2000")
	}
	if len(m.Networks) != 0 && (b.ACPI || b.PCIIDE || m.Architecture == "x86_64") {
		add("networks", "ACPI SCI and ISA NE2000 currently require the same IRQ9")
	}
	for _, network := range m.Networks {
		if network.Kind != "ethernet" || network.Switch == nil || network.MAC == [6]byte{} || network.MAC[0]&1 != 0 {
			add("networks", "NE2000 requires an Ethernet switch and a unicast MAC")
		}
	}
	if len(m.Channels) > 1 {
		add("channels", "cc PC supports one shared-memory channel")
	}
	for _, channel := range m.Channels {
		if channel.Kind != "shared-memory" || channel.Name == "" {
			add("channels", "cc PC requires a named shared-memory channel")
		}
	}
	if m.Display.Mode != "" && m.Display.Mode != "none" && m.Display.Mode != "capturable" {
		add("display", "cc PC supports headless VGA capture")
	}
	for _, required := range m.RequiredCapabilities {
		found := false
		for _, c := range Capabilities() {
			if c == required {
				found = true
			}
		}
		if !found {
			add("required_capabilities", "unsupported capability "+required)
		}
	}
	return issues
}
func (b *Backend) Start(ctx context.Context, m vmm.Machine) (vmm.Driver, error) {
	if issues := b.Validate(m); len(issues) != 0 {
		return nil, &vmm.Error{Code: vmm.ErrorInvalid, Message: "invalid cc machine", Detail: issues[0].Field + ": " + issues[0].Message}
	}
	disk := m.Disks[0]
	if disk.Snapshot {
		limit := b.OverlayLimit
		if limit == 0 {
			limit = 256 << 20
		}
		overlay, err := blockstar.NewOverlayDevice(disk.Device, limit, blockstar.DefaultOverlayChunk)
		if err != nil {
			return nil, err
		}
		disk.Device = overlay
	}
	cpu, err := hypervisor.NewX86(ctx)
	if err != nil {
		return nil, err
	}
	if m.DarwinBoot != nil {
		err = configureDarwinCPU(cpu)
	} else {
		err = configureCPUArchitecture(cpu, m.Architecture == "x86_64")
	}
	if err != nil {
		cpu.Close()
		return nil, err
	}
	lowMemory := min(uint64(m.Memory), uint64(pciMemoryBase))
	regions := []hypervisor.RAMRegion{{Address: 0, Offset: 0, Size: 0xa0000}, {Address: 0xc0000, Offset: 0xc0000, Size: lowMemory - 0xc0000}}
	if uint64(m.Memory) > lowMemory {
		regions = append(regions, hypervisor.RAMRegion{Address: highRAMBase, Offset: lowMemory, Size: uint64(m.Memory) - lowMemory})
	}
	regions = append(regions, hypervisor.RAMRegion{Address: ramfb.Address, Offset: uint64(m.Memory), Size: ramfb.Size})
	total := uint64(m.Memory) + ramfb.Size
	if len(m.Channels) == 1 {
		regions = append(regions, hypervisor.RAMRegion{Address: channelAddress, Offset: total, Size: channelSize})
		total += channelSize
	}
	ram, err := cpu.MapRAMRegions(total, regions)
	if err != nil {
		cpu.Close()
		return nil, err
	}
	platform, err := newPCBoot(cpu, ram[:m.Memory], disk, time.Now, m.DarwinBoot == nil)
	if err != nil {
		cpu.Close()
		return nil, err
	}
	platform.framebuffer = ram[m.Memory : uint64(m.Memory)+ramfb.Size]
	if b.PCIIDE || b.UEFI {
		platform.pciIDE = newPCIIDE()
		if b.IDEModel == "ich7-pata" {
			platform.pciIDE = newICH7PATA()
		}
		platform.ide.dmaEnabled = !b.PIOOnly
		platform.ide.irq = platform.setIDEIRQ
	}
	if b.HPET {
		platform.hpet = newHPET(platform.now(), cpu.SetIRQ)
		if m.DarwinBoot != nil {
			if legacy, ok := cpu.(interface{ SetLegacyTimerReplacement(bool) error }); ok {
				platform.hpet.setLegacy = func(enabled bool) error {
					if err := legacy.SetLegacyTimerReplacement(enabled); err != nil {
						return err
					}
					if enabled && platform.rtcIRQ {
						if err := cpu.SetIRQ(8, false); err != nil {
							return err
						}
						platform.rtcIRQ = false
					}
					platform.rtcNext = time.Time{}
					return nil
				}
			}
		}
	}
	if m.DarwinBoot != nil {
		platform.smc = newSMC(m.DarwinBoot.SMCOSK)
		platform.pciDisplay = newPCIDisplay()
		platform.uhci = newUHCI(platform.inputMemory, cpu.SetIRQ)
	}
	if b.ACPI || b.PCIIDE || b.HPET || b.UEFI || m.Architecture == "x86_64" {
		if err = platform.installACPI(); err != nil {
			cpu.Close()
			return nil, err
		}
	}
	if len(m.Channels) == 1 {
		platform.channelMemory = ram[uint64(m.Memory)+ramfb.Size:]
		platform.channelName = m.Channels[0].Name
		copy(platform.channelMemory, []byte("TRCH\x01\x00\x00\x00"))
	}
	binary.LittleEndian.PutUint32(platform.framebuffer, ramfb.Magic)
	if len(m.Networks) == 1 {
		network := m.Networks[0]
		platform.nic = newNE2000(network.Switch.Connect(), network.MAC, func(level bool) error { return cpu.SetIRQ(9, level) })
	}
	if b.UEFI {
		if err = platform.installUEFI(); err != nil {
			cpu.Close()
			return nil, err
		}
	}
	if m.DarwinBoot != nil {
		if err = platform.installDarwin(m.DarwinBoot); err != nil {
			cpu.Close()
			return nil, err
		}
	}
	return newDriver(ctx, platform, m.StartPaused), nil
}
